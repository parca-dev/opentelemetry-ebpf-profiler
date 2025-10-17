package parcagpu // import "go.opentelemetry.io/ebpf-profiler/parcagpu"

import (
	"context"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// Start starts two goroutines that filter traces coming from ebpf and match them up with timing
// information coming from the parcagpu usdt probes.
func Start(ctx context.Context, traceInCh <-chan *host.Trace,
	tr *tracer.Tracer) chan *host.Trace {
	gpuTimingEvents := tr.GetEbpfMaps()["cuda_timing_events"]
	traceOutChan := make(chan *host.Trace, 1024)

	// Read traces coming from ebpf and send normal traces through
	go func() {
		timer := time.NewTicker(60 * time.Second)
		defer timer.Stop()

		for {
			select {
			case <-timer.C:
				// Periodically clean up all GPU trace fixers
				gpu.MaybeClearAll()
			case <-ctx.Done():
				return
			case t := <-traceInCh:
				if t != nil && t.Origin == support.TraceOriginCuda {
					if err := gpu.AddTrace(t, traceOutChan); err != nil {
						log.Errorf("[parcagpu] failed to add trace for PID %d: %v", t.PID, err)
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
				ev := (*gpu.CuptiTimingEvent)(unsafe.Pointer(&data.RawSample[0]))
				log.Debugf("[cuda]: timing info with id 0x%x for cuda from %d", ev.Id, ev.Pid)
				if completedTrace := gpu.AddTime(ev); completedTrace != nil {
					log.Debugf("[cuda]: trace completed with event: 0x%x", ev.Id)
					traceOutChan <- completedTrace
				}
			}
		}
	}()

	return traceOutChan
}
