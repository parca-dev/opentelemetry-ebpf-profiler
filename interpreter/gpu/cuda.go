package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

type data struct {
	path   string
	link   interpreter.LinkCloser
	probes []pfelf.USDTProbe
}

type instance struct {
	path string
	interpreter.InstanceStubs
	link interpreter.LinkCloser
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
		return &data{path: info.FileName(),
			probes: parcagpuProbes}, nil
	}
	return nil, nil
}

func (d *data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address,
	_ remotememory.RemoteMemory) (ii interpreter.Instance, err error) {
	// Maps usdt probe name to ebpf program name.
	// Use the first character of the probe name as a cookie.
	// 'c' -> cuda_correlation
	// 'k' -> cuda_kernel_exec
	// 'g' -> cuda_graph_exec
	cookies := make([]uint64, len(d.probes))
	progNames := make([]string, len(d.probes))
	for i, probe := range d.probes {
		cookies[i] = uint64(probe.Name[0])
		// Map probe names to specific program names for single-shot mode
		switch probe.Name[0] {
		case 'c':
			progNames[i] = "usdt_parcagpu_cuda_correlation"
		case 'k':
			progNames[i] = "usdt_parcagpu_cuda_kernel"
		case 'g':
			progNames[i] = "usdt_parcagpu_cuda_graph"
		}
	}
	lc, err := ebpf.AttachUSDTProbes(pid, d.path, "cuda_probe", d.probes, cookies, progNames, true)
	if err != nil {
		return nil, err
	}
	log.Debugf("[cuda] parcagpu USDT probes attached for %s", d.path)
	d.link = lc

	return &instance{link: lc, path: d.path}, nil
}

// Detach does nothing, we want the probes attached as long as ANY process is using
// our library.
func (i *instance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	if i.link != nil {
		log.Debugf("[cuda] parcagpu USDT probes closed for %s", i.path)
		if err := i.link.Detach(); err != nil {
			return err
		}
	}
	return nil
}

func (d *data) Unload(ebpf interpreter.EbpfHandler) {
	if d.link != nil {
		log.Debugf("[cuda] parcagpu USDT probes closed for %s", d.path)
		if err := d.link.Unload(); err != nil {
			log.Errorf("error closing cuda usdt link: %s", err)
		}
	}
}
