package parcagpu // import "go.opentelemetry.io/ebpf-profiler/parcagpu"

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/support"
)

type gpuTraceFixer struct {
	mu                  sync.Mutex
	timesAwaitingTraces map[uint32]float32
	tracesAwaitingTimes map[uint32]*host.Trace
}

func (p *gpuTraceFixer) addTrace(trace *host.Trace) *host.Trace {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := trace.ParcaGPUTraceID
	millis, ok := p.timesAwaitingTraces[id]
	if ok {
		delete(p.timesAwaitingTraces, id)
		trace.OffTime = int64(millis * 1000000.0)
		return trace
	}
	p.tracesAwaitingTimes[id] = trace
	return nil
}

func (p *gpuTraceFixer) addTime(id uint32, millis float32) *host.Trace {
	p.mu.Lock()
	defer p.mu.Unlock()
	trace, ok := p.tracesAwaitingTimes[id]
	if ok {
		delete(p.tracesAwaitingTimes, id)
		trace.OffTime = int64(millis * 1000000.0)
		return trace
	}
	p.timesAwaitingTraces[id] = millis
	return nil
}

// uprobes aren't perfect and we may miss matching timing to trace at attach boundary
// so clear them if they get too big.
func (p *gpuTraceFixer) clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.timesAwaitingTraces) > 100 || len(p.tracesAwaitingTimes) > 100 {
		log.Warnf("clearing gpu trace fixer maps, too many entries: %d traces, %d times",
			len(p.tracesAwaitingTimes), len(p.timesAwaitingTraces))
		p.timesAwaitingTraces = map[uint32]float32{}
		p.tracesAwaitingTimes = map[uint32]*host.Trace{}
	}
}

// TODO: have cgo generate this
type kernelTimingEvent struct {
	pid    uint32
	id     uint32
	millis float32
}

// Start starts two goroutines that filter traces coming from ebpf and match them up with timing
// information coming from the launchKernelTiming uprobe.
func Start(ctx context.Context, traceInCh <-chan *host.Trace,
	gpuTimingEvents *ebpf.Map) chan *host.Trace {
	fixer := &gpuTraceFixer{
		timesAwaitingTraces: map[uint32]float32{},
		tracesAwaitingTimes: map[uint32]*host.Trace{},
	}
	traceOutChan := make(chan *host.Trace, 1024)

	// Read traces coming from ebpf and send normal traces through
	go func() {
		// Hack, gpu can't be a regular interpreter since there can be only one and we want to allow
		// python etc to use parcagpu.  So it needs some help in the shutdown department.
		defer gpu.Close()

		timer := time.NewTicker(60 * time.Second)

		for {
			select {
			case <-timer.C:
				// We don't want to leak memory, so we purge the readers map every 60 seconds.
				fixer.clear()
			case <-ctx.Done():
				return
			case t := <-traceInCh:
				if t != nil && t.Origin == support.TraceOriginCuda {
					log.Debugf("got trace with id 0x%x for cuda", t.ParcaGPUTraceID)
					if tr := fixer.addTrace(t); tr != nil {
						log.Debugf("trace complete: 0x%x", tr.ParcaGPUTraceID)
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
				event := (*kernelTimingEvent)(unsafe.Pointer(&data.RawSample[0]))
				log.Debugf("got timing info with id 0x%x for cuda", event.id)
				if tr := fixer.addTime(event.id, event.millis); tr != nil {
					log.Debugf("trace complete: 0x%x", tr.ParcaGPUTraceID)
					traceOutChan <- tr
				}
			}
		}
	}()

	return traceOutChan
}
