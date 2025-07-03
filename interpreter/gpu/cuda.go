package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// Tracks processes that have libparcagpu.so in their mappings and attached uprobes to
// the shim and timing functions to emit faux traces that match the duration of the
// kernel on the GPU.

var linksPerLibraryFile sync.Map

type links struct {
	shim, timing link.Link
}

func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}
	// We use the existence of the .note.stapsdt section to determine if this is a
	// process that has libparcagpu.so loaded. Its cheaper and more reliable than loading
	//  the symbol table.
	if sec := ef.Section(".note.stapsdt"); sec != nil {
		log.Debugf("Found .note.stapsdt section in %s", info.FileName())
		probes, err := pfelf.ParseUSDTProbes(sec)
		if err != nil {
			return nil, err
		}
		for _, probe := range probes {
			log.Debugf("Found USDT probe in %s: %s.%s at 0x%x",
				info.FileName(), probe.Provider, probe.Name, probe.Location)
			if probe.Provider == "parcagpu" && probe.Name == "kernel_launch" {
				log.Infof("Found parcagpu USDT probe in %s: %s.%s at 0x%x",
					info.FileName(), probe.Provider, probe.Name, probe.Location)
				x, err := link.OpenExecutable(info.FileName())
				if err != nil {
					return nil, err
				}

				// get the file identifier of the library
				fileID, err := util.GetOnDiskFileIdentifier(info.FileName())
				if err != nil {
					return nil, fmt.Errorf("failed to get file identifier for %s: %w",
						info.FileName(), err)
				}
				log.Debugf("Library file ID: device=%d, inode=%d", fileID.DeviceID, fileID.InodeNum)

				if _, ok := linksPerLibraryFile.Load(fileID); ok {
					log.Debugf("Links already exist for file (device=%d, inode=%d), skipping",
						fileID.DeviceID, fileID.InodeNum)
					return nil, nil
				}

				shimLink, err := x.Uprobe("shim_inner",
					ebpf.GetProgram("cuda_launch_shim"), &link.UprobeOptions{})
				if err != nil {
					return nil, err
				}

				timingLink, err := x.Uprobe("launchKernelTiming",
					ebpf.GetProgram("cuda_timing_probe"), &link.UprobeOptions{})
				if err != nil {
					return nil, err
				}

				linksPerLibraryFile.Store(fileID, links{
					shim:   shimLink,
					timing: timingLink,
				})
				// We don't return a interpreter.Data here because we don't want to prevent a real
				// interpreter from being attached, these probes will be active for the lifetime of
				// the agent process.
				return nil, nil
			}
		}
	}
	return nil, nil
}

func Close() {
	log.Debugf("Closing GPU interpreter links")
	linksPerLibraryFile.Range(func(_, v interface{}) bool {
		l, ok := v.(links)
		if !ok {
			log.Errorf("Failed to cast links: %v", v)
			return true
		}
		if l.shim != nil {
			if err := l.shim.Close(); err != nil {
				log.Errorf("Failed to close shim link: %v", err)
			}
		}
		if l.timing != nil {
			if err := l.timing.Close(); err != nil {
				log.Errorf("Failed to close timing link: %v", err)
			}
		}
		return true
	})
}
