package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

type data struct {
	probe        pfelf.USDTProbe
	path         string
	shim, timing link.Link
}

type instance struct {
	interpreter.InstanceStubs
}

func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}
	// We use the existence of the .note.stapsdt section to determine if this is a
	// process that has libparcagpu.so loaded. Its cheaper and more reliable than loading
	//  the symbol table.
	if sec := ef.Section(".note.stapsdt"); sec != nil {
		probes, err := pfelf.ParseUSDTProbes(sec)
		if err != nil {
			return nil, err
		}
		for _, probe := range probes {
			if probe.Provider == "parcagpu" && probe.Name == "kernel_launch" {
				return &data{path: info.FileName(), probe: probe}, nil
			}
		}
	}
	return nil, nil
}

func (d *data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address,
	_ remotememory.RemoteMemory) (ii interpreter.Instance, err error) {
	path := fmt.Sprintf("/proc/%v/root/%s", pid, d.path)
	if err := d.attachUprobes(ebpf, path); err != nil {
		log.Errorf("[cuda] parcagpu USDT probe attached failed in %s: %v", path, err)
		return nil, fmt.Errorf("failed to attach uprobes for %s: %w", path, err)
	}
	log.Debugf("[cuda] parcagpu USDT probes in %s", path)
	return &instance{}, nil
}

func (i *instance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	return nil
}

func (d *data) attachUprobes(ebpf interpreter.EbpfHandler, path string) error {
	log.Infof("Found parcagpu USDT probe in %s: %s.%s at 0x%x",
		path, d.probe.Provider, d.probe.Name, d.probe.Location)
	x, err := link.OpenExecutable(path)
	if err != nil {
		return err
	}

	shimLink, err := x.Uprobe("shim_inner",
		ebpf.GetProgram("cuda_launch_shim"), &link.UprobeOptions{})
	if err != nil {
		return err
	}

	timingLink, err := x.Uprobe("launchKernelTiming",
		ebpf.GetProgram("cuda_timing_probe"), &link.UprobeOptions{})
	if err != nil {
		return err
	}
	d.shim = shimLink
	d.timing = timingLink
	return nil
}

func (d *data) Unload(_ interpreter.EbpfHandler) {
	if d.shim != nil {
		if err := d.shim.Close(); err != nil {
			log.Errorf("Failed to close shim link: %v", err)
		}
	}
	if d.timing != nil {
		if err := d.timing.Close(); err != nil {
			log.Errorf("Failed to close timing link: %v", err)
		}
	}
	log.Debugf("[cuda] parcagpu USDT probes closed for %s", d.path)
}
