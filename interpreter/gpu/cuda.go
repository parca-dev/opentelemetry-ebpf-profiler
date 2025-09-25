package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"runtime"

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

		// Validate probe arguments match what cuda.ebpf.c expects
		validateProbeArguments(parcagpuProbes, info.FileName())

		return &data{path: info.FileName(),
			probes: parcagpuProbes}, nil
	}
	return nil, nil
}

// validateProbeArguments checks that the USDT probe arguments match the expectations
// in cuda.ebpf.c and logs errors if they don't match.
func validateProbeArguments(probes []pfelf.USDTProbe, path string) {
	var expectedProbes map[string]string

	switch runtime.GOARCH {
	case "amd64":
		expectedProbes = map[string]string{
			"cuda_correlation": "4@-36(%rbp)",
			"kernel_executed":  "8@%rax 8@%rdx 8@-40(%rbp) 4@%ecx 8@%rsi",
			"graph_executed":   "8@%rax 8@%rdx 8@-64(%rbp) 4@%ecx 4@%esi",
		}
	case "arm64":
		expectedProbes = map[string]string{
			"cuda_correlation": "4@[sp, 36]",
			"kernel_executed":  "8@x1 8@x2 8@[sp, 112] 4@x3 8@x0",
			"graph_executed":   "8@x1 8@x2 8@[sp, 88] 4@x3 4@x0",
		}
	default:
		log.Warnf("[cuda] Unknown architecture %s, cannot validate USDT probe arguments for %s",
			runtime.GOARCH, path)
		return
	}

	probeMap := make(map[string]string)
	for _, probe := range probes {
		probeMap[probe.Name] = probe.Arguments
	}

	for name, expectedArgs := range expectedProbes {
		actualArgs, ok := probeMap[name]
		if !ok {
			log.Errorf("[cuda] Missing expected USDT probe '%s' in %s", name, path)
			continue
		}
		if actualArgs != expectedArgs {
			log.Errorf("[cuda] USDT probe '%s' in %s has incorrect arguments:\n"+
				"  Expected: %s\n"+
				"  Actual:   %s\n"+
				"  This will cause incorrect data collection. cuda.ebpf.c needs to be updated.",
				name, path, expectedArgs, actualArgs)
		}
	}
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
