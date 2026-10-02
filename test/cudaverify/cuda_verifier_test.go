//go:build linux

package cudaverify

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
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

	_, trc := testutils.StartTracer(ctx, t, interpreters, false)
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
	var rec ringbuf.Record

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
					continue
				}
			}
			if len(rec.RawSample) < int(unsafe.Sizeof(gpu.CuptiKernelEvent{})) {
				continue
			}
			ev := (*gpu.CuptiKernelEvent)(unsafe.Pointer(&rec.RawSample[0]))
			if ev.EventType != gpu.EventTypeKernel {
				continue
			}
			events = append(events, *ev)
			t.Logf("Received kernel event: pid=%d id=%d dev=%d stream=%d kernel=%s",
				ev.Pid, ev.Id, ev.Dev, ev.Stream,
				string(ev.KernelName[:bytes.IndexByte(ev.KernelName[:], 0)]))
		}
	nextAttempt:
		if len(events) > 0 {
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
