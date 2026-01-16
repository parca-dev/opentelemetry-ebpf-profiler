package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"errors"
	"fmt"
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
	// eBPF program names for USDT probes
	// These correspond to the function names in cuda.ebpf.c, not the SEC() paths
	USDTProgCudaCorrelation = "cuda_correlation"
	USDTProgCudaKernel      = "cuda_kernel_exec"
	USDTProgCudaProbe       = "cuda_probe"
)

var (
	// gpuFixers maps PID to gpuTraceFixer
	gpuFixers sync.Map
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
	timesAwaitingTraces map[uint32][]CuptiTimingEvent // keyed by correlation ID
	tracesAwaitingTimes map[uint32]*host.Trace        // keyed by correlation ID
}

type data struct {
	path   string
	link   interpreter.LinkCloser
	probes []pfelf.USDTProbe
}

// Instance is the CUDA interpreter instance
type Instance struct {
	interpreter.InstanceStubs
	path string
	pid  libpf.PID
}

// CuptiTimingEvent is the structure received from eBPF via perf buffer
type CuptiTimingEvent struct {
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
	// process that has libparcagpucupti.so loaded.
	probes, err := ef.ParseUSDTProbes()
	if err != nil {
		return nil, err
	}
	if len(probes) > 0 {
		var parcagpuProbes []pfelf.USDTProbe
		for _, probe := range probes {
			if probe.Provider == "parcagpu" {
				parcagpuProbes = append(parcagpuProbes, probe)
			}
		}
		if len(parcagpuProbes) == 0 {
			return nil, nil
		}
		if len(parcagpuProbes) != 2 {
			log.Warnf("Found %d parcagpu USDT probes in %s, need exactly 2: %v", len(parcagpuProbes), info.FileName(), parcagpuProbes)
			return nil, nil
		}

		log.Debugf("Found parcagpu USDT probes in %s: %v", info.FileName(), parcagpuProbes)

		d := &data{
			path:   info.FileName(),
			probes: parcagpuProbes,
		}

		return d, nil
	}
	return nil, nil
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
		switch probe.Name {
		case "cuda_correlation":
			progNames[i] = USDTProgCudaCorrelation
		case "kernel_executed":
			progNames[i] = USDTProgCudaKernel
		default:
			log.Debugf("unknown parcagpu USDT probe name: %s", probe.Name)
		}
	}

	var lc interpreter.LinkCloser
	if d.link == nil {
		var err error
		lc, err = ebpf.AttachUSDTProbes(pid, d.path, USDTProgCudaProbe, d.probes, cookies, progNames)
		if err != nil {
			return nil, err
		}
		log.Debugf("[cuda] parcagpu USDT probes attached for %s", d.path)
		d.link = lc
	} else {
		log.Debugf("[cuda] parcagpu USDT probes already attached for %s", d.path)
	}

	// Create and register fixer for this PID
	fixer := &gpuTraceFixer{
		timesAwaitingTraces: make(map[uint32][]CuptiTimingEvent),
		tracesAwaitingTimes: make(map[uint32]*host.Trace),
	}

	gpuFixers.Store(pid, fixer)
	return &Instance{
		path: d.path,
		pid:  pid,
	}, nil
}

func (i *Instance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	gpuFixers.Delete(i.pid)
	return nil
}

const (
	CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch                = 514
	CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch_ptsz           = 515
	CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_v10000      = 311
	CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_ptsz_v10000 = 312
)

func isGraphLaunch(cbid int32) bool {
	if cbid < 0 {
		// Driver API callback ids are negative
		switch -cbid {
		case CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch, CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch_ptsz:
			return true
		}
	} else {
		switch cbid {
		case CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_v10000, CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_ptsz_v10000:
			return true
		}
	}
	return false
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
	correlationId := uint32(frame.Lineno)
	cbid := int32(frame.Lineno >> 32)

	log.Debugf("[cuda] adding trace with id %d cbid %d (0x%x) for pid %d", correlationId, int(cbid), uint32(cbid), trace.PID)
	f.mu.Lock()
	defer f.mu.Unlock()

	evs, ok := f.timesAwaitingTraces[correlationId]
	if ok && len(evs) > 0 {
		// Process any timing events that arrived before this trace
		for idx := range evs {
			log.Debugf("[cuda] gpu trace completed id %d cbid %d (0x%x) for pid %d",
				correlationId, int(cbid), uint32(cbid), trace.PID)
			traceOutChan <- f.prepTrace(trace, &evs[idx])
		}
		// Always delete the key to avoid nil entries accumulating
		delete(f.timesAwaitingTraces, correlationId)
		// For non-graph launches, we've matched the only timing event, done
		if !isGraphLaunch(cbid) {
			return nil
		}
	}
	// Store trace for future timing events
	f.tracesAwaitingTimes[correlationId] = trace
	return nil
}

// addTime is called when timing info is received from eBPF, to match it with a trace.
func (f *gpuTraceFixer) addTime(ev *CuptiTimingEvent) *host.Trace {
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
	// Sample a few IDs from each map to debug matching issues
	var traceIDs, timeIDs []uint32
	for id := range f.tracesAwaitingTimes {
		traceIDs = append(traceIDs, id)
		if len(traceIDs) >= 5 {
			break
		}
	}
	var graphCount, totalTimeEvents int
	for id, evs := range f.timesAwaitingTraces {
		if len(timeIDs) < 5 {
			timeIDs = append(timeIDs, id)
		}
		for _, ev := range evs {
			totalTimeEvents++
			if ev.Graph != 0 {
				graphCount++
			}
		}
	}
	log.Debugf("[cuda] gpu trace fixer: %d traces waiting, %d time keys (%d events, %d graphs) waiting. Sample trace IDs: %v, time IDs: %v",
		len(f.tracesAwaitingTimes), len(f.timesAwaitingTraces), totalTimeEvents, graphCount, traceIDs, timeIDs)
	if len(f.timesAwaitingTraces) > 10000 || len(f.tracesAwaitingTimes) > 10000 {
		log.Warnf("[cuda] clearing gpu trace fixer maps")
		keys := libpf.MapKeysToSet(f.timesAwaitingTraces)
		// sort keys by correlation ID so we keep the highest (most recent) ones
		slices.SortFunc(keys.ToSlice(), func(a, b uint32) int {
			return int(a) - int(b)
		})
		keySlice := keys.ToSlice()
		if len(keySlice) > 5000 {
			deleteCount := len(keySlice) - 5000
			for _, k := range keySlice[:deleteCount] {
				delete(f.timesAwaitingTraces, k)
			}
		}
		keys = libpf.MapKeysToSet(f.tracesAwaitingTimes)
		slices.SortFunc(keys.ToSlice(), func(a, b uint32) int {
			return int(a) - int(b)
		})
		keySlice = keys.ToSlice()
		if len(keySlice) > 5000 {
			deleteCount := len(keySlice) - 5000
			for _, k := range keySlice[:deleteCount] {
				delete(f.tracesAwaitingTimes, k)
			}
		}
	}
}

// prepTrace prepares a trace with timing information and kernel name.
func (f *gpuTraceFixer) prepTrace(tr *host.Trace, ev *CuptiTimingEvent) *host.Trace {
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
		// Store the interned string directly in the File field (both are 8 bytes)
		istr := libpf.Intern(str)
		// See collect_trace where we always make the first frame a CUDA kernel frame.
		if tr.Frames[0].Type != libpf.CUDAKernelFrame {
			panic("first frame is not a CUDA kernel frame")
		}
		tr.Frames[0].File = host.FileID(*(*uint64)(unsafe.Pointer(&istr)))
	}
	return tr
}

// AddTrace is a static function that delegates to the appropriate fixer for the PID.
// Completed traces are sent directly to traceOutChan.
func AddTrace(trace *host.Trace, traceOutChan chan<- *host.Trace) error {
	pid := trace.PID
	value, ok := gpuFixers.Load(pid)
	if !ok {
		return fmt.Errorf("no GPU fixer found for PID %d", pid)
	}
	fixer := value.(*gpuTraceFixer)
	return fixer.addTrace(trace, traceOutChan)
}

// AddTime is a static function that delegates to the appropriate fixer for the PID.
func AddTime(ev *CuptiTimingEvent) *host.Trace {
	pid := libpf.PID(ev.Pid)
	value, ok := gpuFixers.Load(pid)
	if !ok {
		log.Warnf("no GPU fixer found for PID %d", pid)
		return nil
	}
	fixer := value.(*gpuTraceFixer)
	return fixer.addTime(ev)
}

// MaybeClearAll periodically clears all fixers to avoid memory leaks.
func MaybeClearAll() {
	gpuFixers.Range(func(key, value any) bool {
		fixer := value.(*gpuTraceFixer)
		fixer.maybeClear()
		return true
	})
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
