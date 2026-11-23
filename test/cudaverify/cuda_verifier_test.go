//go:build linux

package cudaverify

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/testutils"
	"go.opentelemetry.io/ebpf-profiler/util"
)

var soPath = flag.String("so-path", "/libparcagpucupti.so", "path to libparcagpucupti.so")

// libparcagpucupti.so is loaded at most once per process: dlclose does not unmap
// it and InitializeInjection only registers its CUPTI callbacks on the first call.
var (
	loadOnce sync.Once
	loadRC   int
)

func TestMain(m *testing.M) {
	flag.Parse()

	code := m.Run()

	if loadRC == 0 && os.Getuid() == 0 {
		cCleanupParcaGPU()
	}

	os.Exit(code)
}

// isMapped reports whether a file with the given base name is mapped into this process.
func isMapped(t *testing.T, path string) bool {
	t.Helper()
	maps, err := os.ReadFile("/proc/self/maps")
	require.NoError(t, err)
	return bytes.Contains(maps, []byte("/"+filepath.Base(path)+"\n"))
}

// hasProbe reports whether the parcagpu library at path defines the named USDT
// probe, so tests of newer probes still pass against older libraries.
func hasProbe(t *testing.T, path, name string) bool {
	t.Helper()
	ef, err := pfelf.Open(path)
	require.NoError(t, err)
	defer ef.Close()
	probes, err := ef.ParseUSDTProbes()
	require.NoError(t, err)
	for _, p := range probes {
		if p.Provider == "parcagpu" && p.Name == name {
			return true
		}
	}
	return false
}

// runEndToEnd exercises the full process-manager driven GPU probe attachment flow:
//
//  1. Start the full tracer pipeline (PID event processor, map monitors, profiling).
//  2. ForceProcessPID to trigger the initial process sync, before
//     libparcagpucupti.so is loaded.
//  3. dlopen libparcagpucupti.so, as CUDA does for CUDA_INJECTION64_PATH. Nothing
//     forces a resync: the GPU interpreter must be discovered through the MMAP
//     event that the new mapping generates.
//  4. Verify GPU interpreter instance is attached, then simulate kernel launches
//     and check that timing events arrive on the perf buffer.
func runEndToEnd(t *testing.T, multiProbe bool) {
	t.Helper()

	if !multiProbe {
		noMulti := false
		util.SetTestOnlyMultiUprobeSupport(&noMulti)
		defer util.SetTestOnlyMultiUprobeSupport(nil)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	interpreters := interpreterconfig.NoInterpreters()
	interpreters.CUDA.Disabled = false
	// The Go interpreter attaches to this (Go) test binary on the initial sync,
	// which gives the wait below a signal that does not depend on the GPU library.
	interpreters.Go.Disabled = false

	blocking := &blockingReporter{}
	trc := testutils.StartTracerWithReporter(ctx, t, interpreters, false, blocking)
	defer trc.Close()

	// Only the first test to run loads the library after the initial sync; later
	// tests find it mapped and discover it on the initial sync instead.
	if isMapped(t, *soPath) {
		t.Logf("%s is already mapped; the late dlopen path is not exercised", *soPath)
	}

	// Trigger initial process sync for our PID so the tracer discovers our
	// mappings. The first Loader call starts the MMAP event monitor.
	pid := libpf.PID(uint32(os.Getpid()))
	trc.ForceProcessPID(pid)

	// Wait until the process manager has processed our PID and attached the Go
	// interpreter instance.
	require.Eventually(t, func() bool {
		instances := trc.GetInterpretersForPID(pid)
		if len(instances) > 0 {
			t.Logf("process synced: %d interpreter(s) attached", len(instances))
			return true
		}
		t.Log("waiting for initial process sync...")
		trc.ForceProcessPID(pid)
		return false
	}, 30*time.Second, 200*time.Millisecond, "process manager never synced our PID")

	// Let any ForceProcessPID still queued from the loop above be processed, so
	// that it cannot be what discovers the library loaded below.
	time.Sleep(time.Second)

	// cuda_blocking_call is opt-in; report every call, not a sample of the
	// short ones. Read once, when the library initializes.
	t.Setenv("PARCAGPU_BLOCKING_CALLS", "1")
	t.Setenv("PARCAGPU_BLOCKING_THRESHOLD_US", "0")
	loadOnce.Do(func() { loadRC = cInitParcaGPU(*soPath) })
	require.Zero(t, loadRC, "loading %s failed", *soPath)

	// Set up ringbuf reader on the cupti_events map BEFORE the dlopen so we
	// don't miss any events.
	cuptiEventsMap := trc.GetEbpfMaps()["cupti_events"]
	require.NotNil(t, cuptiEventsMap, "cupti_events map not found")

	reader, err := ringbuf.NewReader(cuptiEventsMap)
	require.NoError(t, err, "ringbuf.NewReader failed")
	defer reader.Close()

	// Wait until the GPU interpreter instance appears, confirming that the MMAP
	// event for the dlopen'ed library led the process manager to attach the USDT
	// probes. Deliberately no ForceProcessPID here.
	//
	// Attach fails outright if either tail-called program is rejected by the
	// verifier, so an eBPF program that outgrows a kernel's complexity cap shows
	// up here as the GPU instance never appearing, with the verifier log above.
	require.Eventually(t, func() bool {
		instances := trc.GetInterpretersForPID(pid)
		for _, inst := range instances {
			if _, ok := inst.(*gpu.Instance); ok {
				t.Log("GPU interpreter instance attached")
				return true
			}
		}
		t.Logf("waiting for GPU interpreter instance (%d interpreters so far)...", len(instances))
		return false
	}, 30*time.Second, 200*time.Millisecond, "GPU interpreter never attached after dlopen")

	// Simulate kernel launches and wait for timing events.  Retry the
	// simulation several times — on slow CI the uprobes may not be fully
	// active in the kernel immediately after the interpreter is detected.
	var events []gpu.CuptiKernelEvent
	var stats []gpu.CuptiKernelStatsEvent
	var statsNames []string
	var rec ringbuf.Record
	wantStats := hasProbe(t, *soPath, "kernel_stats")
	wantBlocking := hasProbe(t, *soPath, "cuda_blocking_call")
	// parcagpu logs its startup record while loading, before the probes are
	// attached, and replays it to the log probe once they are.
	var logs []string
	wantLog := hasProbe(t, *soPath, "log")
	done := func() bool {
		return len(events) > 0 && (!wantStats || len(stats) > 0) &&
			(!wantBlocking || len(blocking.get()) > 0) && (!wantLog || len(logs) > 0)
	}

	const (
		maxAttempts  = 10
		pollTimeout  = 10 * time.Second
		pollInterval = 200 * time.Millisecond
	)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		t.Logf("simulation attempt %d/%d", attempt, maxAttempts)

		// Simulate a kernel launch (fires cuda_correlation USDT).
		cSimulateKernelLaunch(42)

		// Simulate buffer completion (fires kernel_executed + activity_batch USDTs).
		cSimulateBufferCompletion(42, 0, 7, "testKernel")

		// Simulate a 2 ms cudaStreamSynchronize (fires cuda_blocking_call,
		// whose trace reaches the reporter rather than cupti_events).
		if wantBlocking {
			cSimulateStreamSync(43, 2000)
		}

		// Poll ringbuf reader for events. Filter to EVENT_TYPE_KERNEL — the
		// same ringbuf carries cubin/pc_sample/error events too in production,
		// but those don't fire in this simulation.
		deadline := time.After(pollTimeout)
		for {
			reader.SetDeadline(time.Now().Add(pollInterval))
			err := reader.ReadInto(&rec)
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					goto nextAttempt
				}
				select {
				case <-deadline:
					goto nextAttempt
				default:
					if done() {
						goto nextAttempt
					}
					continue
				}
			}
			if len(rec.RawSample) >= int(unsafe.Sizeof(gpu.CuptiKernelStatsEvent{})) &&
				binary.NativeEndian.Uint32(rec.RawSample[:4]) == gpu.EventTypeKernelStats {
				ev := (*gpu.CuptiKernelStatsEvent)(unsafe.Pointer(&rec.RawSample[0]))
				name := rec.RawSample[unsafe.Sizeof(gpu.CuptiKernelStatsEvent{}):]
				if idx := bytes.IndexByte(name, 0); idx >= 0 {
					name = name[:idx]
				}
				stats = append(stats, *ev)
				statsNames = append(statsNames, string(name))
				t.Logf("Received kernel_stats event: pid=%d seq=%d dev=%d stream=%d execs=%d total_ns=%d kernel=%s",
					ev.Pid, ev.Seq, ev.DeviceID, ev.StreamID, ev.Executions, ev.TotalNs, name)
				if done() {
					goto nextAttempt
				}
				continue
			}
			if len(rec.RawSample) >= int(unsafe.Sizeof(gpu.CuptiLogEvent{})) &&
				binary.NativeEndian.Uint32(rec.RawSample[:4]) == gpu.EventTypeLog {
				ev := (*gpu.CuptiLogEvent)(unsafe.Pointer(&rec.RawSample[0]))
				if ev.Pid == uint32(pid) {
					line := gpu.FormatLogEvent(ev)
					t.Logf("Received log event: level=%d %s", ev.Level, line)
					if ev.Level == gpu.LogLevelInfo && strings.Contains(line, " active: ") {
						logs = append(logs, line)
					}
				}
				if done() {
					goto nextAttempt
				}
				continue
			}
			if len(rec.RawSample) < int(unsafe.Sizeof(gpu.CuptiKernelEvent{})) {
				continue
			}
			ev := (*gpu.CuptiKernelEvent)(unsafe.Pointer(&rec.RawSample[0]))
			// Other CUDA processes on the machine are traced too.
			if ev.EventType != gpu.EventTypeKernel || ev.Pid != uint32(pid) {
				continue
			}
			events = append(events, *ev)
			t.Logf("Received kernel event: pid=%d id=%d dev=%d stream=%d kernel=%s",
				ev.Pid, ev.Id, ev.Dev, ev.Stream,
				string(ev.KernelName[:bytes.IndexByte(ev.KernelName[:], 0)]))
			if done() {
				goto nextAttempt
			}
		}
	nextAttempt:
		if done() {
			break
		}
		t.Logf("no events after attempt %d, retrying...", attempt)
	}

	require.NotEmpty(t, events, "no kernel events received from cupti_events ringbuf after %d attempts", maxAttempts)

	// Verify at least one event matches our simulated kernel.
	found := false
	for _, ev := range events {
		nameBytes := ev.KernelName[:]
		if idx := bytes.IndexByte(nameBytes, 0); idx >= 0 {
			nameBytes = nameBytes[:idx]
		}
		if ev.Id == 42 && ev.Dev == 0 && ev.Stream == 7 &&
			string(nameBytes) == "testKernel" {
			found = true
			break
		}
	}
	require.True(t, found,
		"expected timing event with correlation_id=42, device_id=0, stream_id=7, kernel_name=testKernel; got %+v", events)

	checkBlockingCalls(t, wantBlocking, blocking.get())

	if wantLog {
		require.NotEmpty(t, logs, "parcagpu's startup record never reached the log probe")
	} else {
		t.Logf("%s has no log probe; skipping log checks", *soPath)
	}

	if !wantStats {
		t.Logf("%s has no kernel_stats probe; skipping kernel_stats checks", *soPath)
		return
	}
	require.NotEmpty(t, stats, "no kernel_stats events received")
	found = false
	for i, ev := range stats {
		if ev.Pid == uint32(pid) && ev.DeviceID == 0 && ev.StreamID == 7 &&
			ev.Executions >= 1 && statsNames[i] == "testKernel" {
			found = true
			break
		}
	}
	require.True(t, found,
		"expected kernel_stats event with device_id=0, stream_id=7, executions>=1, kernel_name=testKernel; got %+v %v",
		stats, statsNames)
}

// blockingTrace is what the test keeps of a cuda_blocking_call trace.
type blockingTrace struct {
	call   gpu.BlockingCall
	labels map[string]string
	frames int
}

// blockingReporter keeps the CUDA blocking-call traces the tracer reports
// and drops the rest without blocking it. It reads each trace while its
// ContextValues are valid, in ReportTraceEvent.
type blockingReporter struct {
	mu     sync.Mutex
	traces []blockingTrace
}

func (r *blockingReporter) ReportTraceEvent(trace *libpf.Trace,
	meta *samples.TraceEventMeta) error {
	if meta.ProfileType != gpu.ProfileTypeCudaBlocking {
		return nil
	}
	call, ok := gpu.ParseBlockingCall(meta)
	if !ok {
		return nil
	}
	gpu.DecorateBlockingTrace(trace, meta)
	labels := make(map[string]string, len(trace.CustomLabels))
	for k, v := range trace.CustomLabels {
		labels[k.String()] = v.String()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.traces = append(r.traces, blockingTrace{call: call, labels: labels,
		frames: len(trace.Frames)})
	return nil
}

func (r *blockingReporter) get() []blockingTrace {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]blockingTrace(nil), r.traces...)
}

// checkBlockingCalls verifies the 2 ms cudaStreamSynchronize came back as a
// blocking-call trace with the caller's stack, weighted by its duration.
func checkBlockingCalls(t *testing.T, want bool, traces []blockingTrace) {
	t.Helper()
	if !want {
		t.Logf("%s has no cuda_blocking_call probe; skipping blocking-call checks", *soPath)
		return
	}
	require.NotEmpty(t, traces, "no cuda_blocking_call traces received")
	for _, bt := range traces {
		t.Logf("Received cuda_blocking_call trace: %+v labels=%v frames=%d",
			bt.call, bt.labels, bt.frames)
		// cudaStreamSynchronize_v3020; with a 0 threshold every call is
		// reported at its own duration.
		if bt.call.CBID == 131 && bt.call.WeightNs >= 2_000_000 &&
			bt.call.WeightNs == bt.call.DurationNs && bt.frames > 0 &&
			bt.labels["cuda_api"] == "cudaStreamSynchronize" {
			return
		}
	}
	t.Fatalf("no cuda_blocking_call trace for a >=2ms cudaStreamSynchronize with a stack")
}

// TestCUDAEndToEndSingleShot verifies that CUDA USDT probes fire correctly
// using individual per-probe attachment (kernel 5.15+).
func TestCUDAEndToEndSingleShot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load eBPF programs")
	}
	if !util.HasBpfGetAttachCookie() {
		t.Skip("requires kernel support for bpf_get_attach_cookie (5.15+)")
	}

	runEndToEnd(t, false)
}

// TestCUDAEndToEndMultiProbe verifies that CUDA USDT probes fire correctly
// using multi-uprobe attachment with tail calls (kernel 6.6+).
func TestCUDAEndToEndMultiProbe(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load eBPF programs")
	}
	if !util.HasBpfGetAttachCookie() {
		t.Skip("requires kernel support for bpf_get_attach_cookie (5.15+)")
	}
	if !util.HasMultiUprobeSupport() {
		t.Skip("requires kernel support for uprobe multi-attach (6.6+)")
	}

	runEndToEnd(t, true)
}
