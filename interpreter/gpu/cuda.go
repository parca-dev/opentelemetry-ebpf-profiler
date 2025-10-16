package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"unsafe"

	"github.com/ianlancetaylor/demangle"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/util"
)

const (
	GRAPH_LAUNCH_CBID = 311
)

var (
	// Global map of data instances, keyed by path
	// This mutex also protects all pidToFixer maps within each data instance
	gpuFixerMu    sync.RWMutex
	dataInstances = make(map[string]*data)
)

// gpuTraceFixer matches traces with timing information for a specific PID.
// We use a single fixer per PID because CUDA correlation IDs are unique per process
// across all devices and streams.
// See: https://docs.nvidia.com/cupti/api/structCUpti__ActivityKernel.html
// The correlationId field: "Each function invocation is assigned a unique correlation ID
// that is identical to the correlation ID in the driver or runtime API activity record
// that launched the kernel."
type gpuTraceFixer struct {
	mu                  sync.Mutex
	timesAwaitingTraces map[uint32][]KernelTimingEvent // keyed by correlation ID
	tracesAwaitingTimes map[uint32]*host.Trace         // keyed by correlation ID
}

type data struct {
	path   string
	link   interpreter.LinkCloser
	probes []pfelf.USDTProbe

	// Map of PID to gpuTraceFixer (protected by gpuFixerMu)
	pidToFixer map[libpf.PID]*gpuTraceFixer
}

// Instance is the CUDA interpreter instance
type Instance struct {
	interpreter.InstanceStubs
	path string
	link interpreter.LinkCloser
	pid  libpf.PID
}

// KernelTimingEvent is the structure received from eBPF via perf buffer
type KernelTimingEvent struct {
	Pid                     uint32
	Id                      uint32
	Start, End, GraphNodeId uint64
	Dev, Stream, Graph      uint32
	KernelName              [256]byte
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
		if len(parcagpuProbes) != 2 {
			return nil, nil
		}

		// Validate probe arguments match what cuda.ebpf.c expects
		if err := validateProbeArguments(parcagpuProbes, info.FileName()); err != nil {
			return nil, err
		}

		d := &data{
			path:       info.FileName(),
			probes:     parcagpuProbes,
			pidToFixer: make(map[libpf.PID]*gpuTraceFixer),
		}

		// Register in global map
		gpuFixerMu.Lock()
		dataInstances[d.path] = d
		gpuFixerMu.Unlock()

		return d, nil
	}
	return nil, nil
}

// validateProbeArguments checks that the USDT probe arguments match the expectations
// in cuda.ebpf.c and returns an error if they don't match.
func validateProbeArguments(probes []pfelf.USDTProbe, path string) error {
	var expectedProbes map[string]string

	switch runtime.GOARCH {
	case "amd64":
		expectedProbes = map[string]string{
			"cuda_correlation": "4@-44(%rbp) 4@-64(%rbp) 8@-40(%rbp)",
			"kernel_executed":  "8@%rax 8@%rdx 4@%ecx 4@%esi 4@%edi 4@%r8d 8@%r9 8@%r10",
		}
	case "arm64":
		expectedProbes = map[string]string{
			"cuda_correlation": "4@[sp, 60] 4@[sp, 32] 8@[sp, 64]",
			"kernel_executed":  "8@x1 8@x2 4@x3 4@x4 4@x5 4@x6 8@x7 8@x0",
		}
	default:
		return fmt.Errorf("unknown architecture %s, cannot validate USDT probe arguments for %s",
			runtime.GOARCH, path)
	}

	probeMap := make(map[string]string)
	for _, probe := range probes {
		probeMap[probe.Name] = probe.Arguments
	}

	for name, expectedArgs := range expectedProbes {
		actualArgs, ok := probeMap[name]
		if !ok {
			return fmt.Errorf("missing expected USDT probe '%s' in %s", name, path)
		}
		if actualArgs != expectedArgs {
			return fmt.Errorf("USDT probe '%s' in %s has incorrect arguments: "+
				"expected: %s"+
				"actual: %s",
				name, path, expectedArgs, actualArgs)
		}
	}
	return nil
}

func (d *data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address,
	_ remotememory.RemoteMemory) (interpreter.Instance, error) {
	// Maps usdt probe name to ebpf program name.
	// Use the first character of the probe name as a cookie.
	// 'c' -> cuda_correlation
	// 'k' -> cuda_kernel_exec
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
		}
	}
	lc, err := ebpf.AttachUSDTProbes(pid, d.path, "cuda_probe", d.probes, cookies, progNames, true)
	if err != nil {
		return nil, err
	}
	log.Debugf("[cuda] parcagpu USDT probes attached for %s", d.path)
	d.link = lc

	// Create and register fixer for this PID
	fixer := &gpuTraceFixer{
		timesAwaitingTraces: make(map[uint32][]KernelTimingEvent),
		tracesAwaitingTimes: make(map[uint32]*host.Trace),
	}

	// Use global mutex to protect pidToFixer map
	gpuFixerMu.Lock()
	d.pidToFixer[pid] = fixer
	gpuFixerMu.Unlock()

	return &Instance{
		link: lc,
		path: d.path,
		pid:  pid,
	}, nil
}

// Detach removes the fixer for this PID and closes the link if needed.
func (i *Instance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	// Remove fixer for this PID
	gpuFixerMu.Lock()
	d, ok := dataInstances[i.path]
	if ok {
		delete(d.pidToFixer, i.pid)
	}
	gpuFixerMu.Unlock()

	if i.link != nil {
		log.Debugf("[cuda] parcagpu USDT probes closed for %s", i.path)
		if err := i.link.Detach(); err != nil {
			return err
		}
	}
	return nil
}

// addTrace is called when a CUDA trace is received, to match it with timing info.
// Sends completed traces directly to the output channel (may be multiple for graph launches).
func (f *gpuTraceFixer) addTrace(trace *host.Trace, traceOutChan chan<- *host.Trace) error {
	if len(trace.Frames) == 0 {
		return errors.New("no frames in trace")
	}
	frame := trace.Frames[0]
	if frame.Type != libpf.CUDAKernelFrame {
		return errors.New("first frame is not a CUDA kernel frame")
	}
	cudaId := uint32(frame.Lineno)
	cbid := uint32(frame.Lineno >> 32)

	log.Debugf("[cuda] adding trace with id %d cbid %d for pid %d", cudaId, cbid, trace.PID)
	f.mu.Lock()
	defer f.mu.Unlock()

	evs, ok := f.timesAwaitingTraces[cudaId]
	if ok {
		if cbid != GRAPH_LAUNCH_CBID {
			delete(f.timesAwaitingTraces, cudaId)
		}
		for idx := range evs {
			log.Debugf("[cuda] gpu trace completed id %d cbid %d for pid %d",
				cudaId, cbid, trace.PID)
			traceOutChan <- f.prepTrace(trace, &evs[idx])
		}
		f.timesAwaitingTraces[cudaId] = nil
		return nil
	}
	f.tracesAwaitingTimes[cudaId] = trace
	return nil
}

// addTime is called when timing info is received from eBPF, to match it with a trace.
func (f *gpuTraceFixer) addTime(ev *KernelTimingEvent) *host.Trace {
	f.mu.Lock()
	defer f.mu.Unlock()

	trace, ok := f.tracesAwaitingTimes[ev.Id]
	if ok {
		if ev.Graph == 0 {
			delete(f.tracesAwaitingTimes, ev.Id)
		}
		return f.prepTrace(trace, ev)
	}
	f.timesAwaitingTraces[ev.Id] = append(f.timesAwaitingTraces[ev.Id], *ev)
	return nil
}

// maybeClear clears the maps if they get too big.
func (f *gpuTraceFixer) maybeClear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.timesAwaitingTraces) > 100 || len(f.tracesAwaitingTimes) > 100 {
		log.Warnf("[cuda] clearing gpu trace fixer maps, too many entries: %d traces, %d times",
			len(f.tracesAwaitingTimes), len(f.timesAwaitingTraces))
		keys := libpf.MapKeysToSet(f.timesAwaitingTraces)
		// sort keys by correlation ID so we keep the highest (most recent) ones
		slices.SortFunc(keys.ToSlice(), func(a, b uint32) int {
			return int(a) - int(b)
		})
		keySlice := keys.ToSlice()
		if len(keySlice) > 50 {
			deleteCount := len(keySlice) - 50
			log.Debugf(
				"[cuda] timesAwaitingTraces: deleting %d entries (IDs %d-%d), "+
					"keeping %d entries (IDs %d-%d)",
				deleteCount, keySlice[0], keySlice[deleteCount-1],
				50, keySlice[deleteCount], keySlice[len(keySlice)-1])
			for _, k := range keySlice[:deleteCount] {
				delete(f.timesAwaitingTraces, k)
			}
		}
		keys = libpf.MapKeysToSet(f.tracesAwaitingTimes)
		slices.SortFunc(keys.ToSlice(), func(a, b uint32) int {
			return int(a) - int(b)
		})
		keySlice = keys.ToSlice()
		if len(keySlice) > 50 {
			deleteCount := len(keySlice) - 50
			log.Debugf(
				"[cuda] tracesAwaitingTimes: deleting %d entries (IDs %d-%d), "+
					"keeping %d entries (IDs %d-%d)",
				deleteCount, keySlice[0], keySlice[deleteCount-1],
				50, keySlice[deleteCount], keySlice[len(keySlice)-1])
			for _, k := range keySlice[:deleteCount] {
				delete(f.tracesAwaitingTimes, k)
			}
		}
	}
}

// prepTrace prepares a trace with timing information and kernel name.
func (f *gpuTraceFixer) prepTrace(tr *host.Trace, ev *KernelTimingEvent) *host.Trace {
	if ev.Graph != 0 {
		// Graphs can have many kernels with same correlation ID
		clone := *tr
		tr = &clone
	}
	tr.OffTime = int64(ev.End - ev.Start)
	if tr.CustomLabels == nil {
		tr.CustomLabels = make(map[string]string)
	}

	tr.CustomLabels["cuda_device"] = strconv.FormatUint(uint64(ev.Dev), 10)
	if ev.Stream != 0 {
		tr.CustomLabels["cuda_stream"] = strconv.FormatUint(uint64(ev.Stream), 10)
	}
	if ev.Graph != 0 {
		tr.CustomLabels["cuda_graph"] = strconv.FormatUint(uint64(ev.Graph), 10)
		tr.CustomLabels["cuda_id"] = strconv.FormatUint(uint64(ev.Id), 10)
	}
	if len(ev.KernelName) > 0 {
		str := util.GoString(ev.KernelName[:])
		demstr, err := demangle.ToString(
			str, demangle.NoParams, demangle.NoEnclosingParams)
		if err != nil {
			log.Debugf("failed to demangle cuda kernel name %q: %v", str, err)
		} else {
			str = demstr
		}
		// Store the interned string directly in the uint64 field (both are 8 bytes)
		istr := libpf.Intern(str)
		tr.Frames[0].File = host.FileID(*(*uint64)(unsafe.Pointer(&istr)))
		tr.Frames[0].LJCalleePC = ev.Graph
	}
	return tr
}

// AddTrace is a static function that delegates to the appropriate fixer for the PID.
// Completed traces are sent directly to traceOutChan.
func AddTrace(trace *host.Trace, traceOutChan chan<- *host.Trace) error {
	pid := trace.PID

	// Iterate through all data instances and look for the fixer
	gpuFixerMu.RLock()
	defer gpuFixerMu.RUnlock()

	for _, d := range dataInstances {
		fixer, ok := d.pidToFixer[pid]
		if ok {
			return fixer.addTrace(trace, traceOutChan)
		}
	}

	return fmt.Errorf("no GPU fixer found for PID %d", pid)
}

// AddTime is a static function that delegates to the appropriate fixer for the PID.
func AddTime(ev *KernelTimingEvent) *host.Trace {
	pid := libpf.PID(ev.Pid)

	// Iterate through all data instances and look for the fixer
	gpuFixerMu.RLock()
	defer gpuFixerMu.RUnlock()

	for _, d := range dataInstances {
		fixer, ok := d.pidToFixer[pid]
		if ok {
			return fixer.addTime(ev)
		}
	}

	return nil
}

// MaybeClearAll periodically clears all fixers to avoid memory leaks.
func MaybeClearAll() {
	gpuFixerMu.RLock()
	defer gpuFixerMu.RUnlock()

	for _, d := range dataInstances {
		fixers := make([]*gpuTraceFixer, 0, len(d.pidToFixer))
		for _, fixer := range d.pidToFixer {
			fixers = append(fixers, fixer)
		}

		for _, fixer := range fixers {
			fixer.maybeClear()
		}
	}
}

func (i *Instance) Symbolize(f *host.Frame, frames *libpf.Frames) error {
	if f.Type != libpf.CUDAKernelFrame {
		return interpreter.ErrMismatchInterpreterType
	}
	cudaId := uint64(f.Lineno)
	correlationId := uint32(cudaId)
	callbackType := uint32(cudaId >> 32)
	// Extract the libpf.String directly from the uint64 field (both are 8 bytes)
	fileIDAsUint64 := uint64(f.File)
	internStr := *(*libpf.String)(unsafe.Pointer(&fileIDAsUint64))
	log.Debugf("symbolizing cuda kernel frame with correlation ID %d (callback type %d) %s",
		correlationId, callbackType, internStr)

	frames.Append(&libpf.Frame{
		Type:            libpf.CUDAKernelFrame,
		AddressOrLineno: f.Lineno,
		FunctionName:    internStr,
	})
	// If we have a graph callback add a frame we can turn into cudaGraph-###
	if callbackType == 311 {
		frames.Append(&libpf.Frame{
			Type:         libpf.CUDAKernelFrame,
			FunctionName: libpf.Intern(fmt.Sprintf("cudaGraph-%d", f.LJCalleePC)),
		})
	}
	return nil
}

func (d *data) Unload(ebpf interpreter.EbpfHandler) {
	// Unregister from global map
	gpuFixerMu.Lock()
	delete(dataInstances, d.path)
	gpuFixerMu.Unlock()

	if d.link != nil {
		log.Debugf("[cuda] parcagpu USDT probes closed for %s", d.path)
		if err := d.link.Unload(); err != nil {
			log.Errorf("error closing cuda usdt link: %s", err)
		}
	}
}
