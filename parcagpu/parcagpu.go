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
	"go.opentelemetry.io/ebpf-profiler/support"
)

type mapKey struct {
	pid uint32
	id  uint32
}

type gpuTraceFixer struct {
	mu                  sync.Mutex
	timesAwaitingTraces map[mapKey]uint64
	tracesAwaitingTimes map[mapKey]*host.Trace
}

func (p *gpuTraceFixer) addTrace(trace *host.Trace) *host.Trace {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := mapKey{uint32(trace.PID), trace.ParcaGPUTraceID}
	nanos, ok := p.timesAwaitingTraces[key]
	if ok {
		delete(p.timesAwaitingTraces, key)
		trace.OffTime = int64(nanos)
		return trace
	}
	p.tracesAwaitingTimes[key] = trace
	return nil
}

func (p *gpuTraceFixer) addTime(key mapKey, nanos uint64) *host.Trace {
	p.mu.Lock()
	defer p.mu.Unlock()
	trace, ok := p.tracesAwaitingTimes[key]
	if ok {
		delete(p.tracesAwaitingTimes, key)
		trace.OffTime = int64(nanos)
		return trace
	}
	p.timesAwaitingTraces[key] = nanos
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
		p.timesAwaitingTraces = map[mapKey]uint64{}
		p.tracesAwaitingTimes = map[mapKey]*host.Trace{}
	}
}

// TODO: have cgo generate this
type kernelTimingEvent struct {
	pid        uint32
	id         uint32
	durationNs uint64
}

// Start starts two goroutines that filter traces coming from ebpf and match them up with timing
// information coming from the parcagpuKernelExecuted uprobe.
func Start(ctx context.Context, traceInCh <-chan *host.Trace,
	gpuTimingEvents *ebpf.Map) chan *host.Trace {
	fixer := &gpuTraceFixer{
		timesAwaitingTraces: map[mapKey]uint64{},
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
				fixer.clear()
			case <-ctx.Done():
				return
			case t := <-traceInCh:
				if t != nil && t.Origin == support.TraceOriginCuda {
					log.Debugf("[cuda]: got trace with id 0x%x for cuda from pid: %d", t.ParcaGPUTraceID, t.PID)
					if tr := fixer.addTrace(t); tr != nil {
						log.Debugf("[cuda]: trace complete: 0x%x", tr.ParcaGPUTraceID)
						traceOutChan <- tr
					}
				} else {
					traceOutChan <- t
				}
			}
		}
		log.Debugf("[cuda]: trace reader stopped, map contents %+v\n", fixer)
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
				log.Debugf("[cuda]: got timing info with id 0x%x for cuda from %d", event.id, event.pid)
				if tr := fixer.addTime(mapKey{event.pid, event.id}, event.durationNs); tr != nil {
					log.Debugf("[cuda]: trace complete: 0x%x", tr.ParcaGPUTraceID)
					traceOutChan <- tr
				}
			}
		}
		log.Debugf("[cuda]: event reader stopped, map contents %+v\n", fixer)
	}()

	return traceOutChan
}
