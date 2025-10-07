package parcagpu // import "go.opentelemetry.io/ebpf-profiler/parcagpu"

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/support"
)

type mapKey struct {
	pid uint32
	id  uint32
}

type gpuTraceFixer struct {
	mu                  sync.Mutex
	timesAwaitingTraces map[mapKey]kernelTimingEvent
	tracesAwaitingTimes map[mapKey]*host.Trace
}

func (p *gpuTraceFixer) addTrace(trace *host.Trace) *host.Trace {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := mapKey{uint32(trace.PID), trace.ParcaGPUTraceID}
	ev, ok := p.timesAwaitingTraces[key]
	if ok {
		delete(p.timesAwaitingTraces, key)
		trace.OffTime = int64(ev.end - ev.start)
		prepTrace(trace, &ev)
		return trace
	}
	p.tracesAwaitingTimes[key] = trace
	return nil
}

func (p *gpuTraceFixer) addTime(key mapKey, ev *kernelTimingEvent) *host.Trace {
	p.mu.Lock()
	defer p.mu.Unlock()
	trace, ok := p.tracesAwaitingTimes[key]
	if ok {
		delete(p.tracesAwaitingTimes, key)
		prepTrace(trace, ev)
		return trace
	}
	p.timesAwaitingTraces[key] = *ev
	return nil
}

// maybeClear clears the maps if they get too big. uprobes aren't perfect and
// we may miss matching timing to trace at attach boundary.
func (p *gpuTraceFixer) maybeClear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.timesAwaitingTraces) > 100 || len(p.tracesAwaitingTimes) > 100 {
		log.Warnf("[parcagpu] clearing gpu trace fixer maps, too many entries: %d traces, %d times",
			len(p.tracesAwaitingTimes), len(p.timesAwaitingTraces))
		p.timesAwaitingTraces = map[mapKey]kernelTimingEvent{}
		p.tracesAwaitingTimes = map[mapKey]*host.Trace{}
	}
}

// TODO: have cgo generate this
type kernelTimingEvent struct {
	pid                uint32
	id                 uint32
	start, end         uint64
	dev, stream, graph uint32
	kernelName         [128]byte
}

func prepTrace(tr *host.Trace, ev *kernelTimingEvent) {
	tr.OffTime = int64(ev.end - ev.start)
	if tr.CustomLabels == nil {
		tr.CustomLabels = make(map[string]string)
	}

	tr.CustomLabels["cuda_device"] = strconv.FormatUint(uint64(ev.dev), 10)
	if ev.stream != 0 {
		tr.CustomLabels["cuda_stream"] = strconv.FormatUint(uint64(ev.stream), 10)
	}
	if ev.graph != 0 {
		tr.CustomLabels["cuda_graph"] = strconv.FormatUint(uint64(ev.graph), 10)
	}
	if len(ev.kernelName) > 0 {
		// TODO: is there a better way to pass this through?
		tr.CustomLabels["_temp_cuda_kernel"] = string(ev.kernelName[:])
		// ConvertTrace will add a pseudo-frame for the kernel.
		tr.Frames = append([]host.Frame{{
			Type: libpf.CUDAKernelFrame,
		}}, tr.Frames...)
	}
}

// Start starts two goroutines that filter traces coming from ebpf and match them up with timing
// information coming from the parcagpuKernelExecuted uprobe.
func Start(ctx context.Context, traceInCh <-chan *host.Trace,
	gpuTimingEvents *ebpf.Map) chan *host.Trace {
	fixer := &gpuTraceFixer{
		timesAwaitingTraces: map[mapKey]kernelTimingEvent{},
		tracesAwaitingTimes: map[mapKey]*host.Trace{},
	}
	traceOutChan := make(chan *host.Trace, 1024)

	// Read traces coming from ebpf and send normal traces through
	go func() {
		timer := time.NewTicker(60 * time.Second)

		for {
			select {
			case <-timer.C:
				// We don't want to leak memory, so we purge the readers map every 60 seconds.
				fixer.maybeClear()
			case <-ctx.Done():
				return
			case t := <-traceInCh:
				if t != nil && t.Origin == support.TraceOriginCuda {
					log.Debugf("[cuda]: got trace with id 0x%x for cuda from pid: %d",
						t.ParcaGPUTraceID, t.PID)
					if tr := fixer.addTrace(t); tr != nil {
						log.Debugf("[cuda]: trace completed with trace: 0x%x", tr.ParcaGPUTraceID)
						traceOutChan <- tr
					}
				} else {
					traceOutChan <- t
				}
			}
		}
	}()

	eventReader, err := perf.NewReader(gpuTimingEvents, 1024 /* perCPUBufferSize */)
	if err != nil {
		log.Fatalf("Failed to setup perf reporting via %s: %v", gpuTimingEvents, err)
	}

	var lostEventsCount, readErrorCount, noDataCount atomic.Uint64
	go func() {
		var data perf.Record
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if err := eventReader.ReadInto(&data); err != nil {
					readErrorCount.Add(1)
					continue
				}
				if data.LostSamples != 0 {
					lostEventsCount.Add(data.LostSamples)
					continue
				}
				if len(data.RawSample) == 0 {
					noDataCount.Add(1)
					continue
				}
				ev := (*kernelTimingEvent)(unsafe.Pointer(&data.RawSample[0]))
				log.Debugf("[cuda]: timing info with id 0x%x for cuda from %d", ev.id, ev.pid)
				if tr := fixer.addTime(mapKey{ev.pid, ev.id}, ev); tr != nil {
					log.Debugf("[cuda]: trace completed with event: 0x%x", tr.ParcaGPUTraceID)
					traceOutChan <- tr
				}
			}
		}
	}()

	return traceOutChan
}
