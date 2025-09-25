package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

type data struct {
	path string
	link link.Link
}

type instance struct {
	interpreter.InstanceStubs
}

func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}
	// We use the existence of the .note.stapsdt section to determine if this is a
	// process that has libparcagpucupti.so loaded. Its cheaper and more reliable than loading
	// the symbol table.
	if sec := ef.Section(".note.stapsdt"); sec != nil {
		probes, err := pfelf.ParseUSDTProbes(sec)
		if err != nil {
			return nil, err
		}
		var parcagpuProbes []pfelf.USDTProbe
		for _, probe := range probes {
			if probe.Provider == "parcagpu" {
				parcagpuProbes = append(parcagpuProbes, probe)
			}
		}
		if len(parcagpuProbes) != 3 {
			return nil, nil
		}
		// Maps usdt probe name to ebpf program name.
		var cookies []uint64
		// Use the first character of the probe name as a cookie.
		// 'c' -> cuda_correlation
		// 'k' -> cuda_kernel_exec
		// 'g' -> cuda_graph_exec
		for _, probe := range probes {
			cookies = append(cookies, uint64(probe.Name[0]))
		}
		link, err := ebpf.AttachUSDTProbes(0, info.FileName(), "cuda_probe", probes, cookies)
		if err != nil {
			return nil, err
		}
		log.Debugf("[cuda] parcagpu USDT probes attached for %s", info.FileName())
		return &data{path: info.FileName(),
			link: link}, nil
	}
	return nil, nil
}

func (d *data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address,
	_ remotememory.RemoteMemory) (ii interpreter.Instance, err error) {
	return &instance{}, nil
}

// Detach does nothing, we want the probes attached as long as ANY process is using
// our library.
func (i *instance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	return nil
}

func (d *data) Unload(ebpf interpreter.EbpfHandler) {
	log.Debugf("[cuda] parcagpu USDT probes closed for %s", d.path)
	if err := d.link.Close(); err != nil {
		log.Errorf("error closing cuda usdt link: %s", err)
	}
}
