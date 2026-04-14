//go:build linux

package cudaverify

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/testutils"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/util"
)

var soPath = flag.String("so-path", "/libparcagpucupti.so", "path to libparcagpucupti.so")

func TestMain(m *testing.M) {
	flag.Parse()

	if os.Getuid() == 0 {
		rc := cInitParcaGPU(*soPath)
		if rc != 0 {
			os.Exit(1)
		}
	}

	code := m.Run()

	if os.Getuid() == 0 {
		cCleanupParcaGPU()
	}

	os.Exit(code)
}

// runEndToEnd exercises the full process-manager driven GPU probe attachment flow:
//
//  1. Start the full tracer pipeline (PID event processor, map monitors, profiling).
//  2. ForceProcessPID to trigger process sync — the tracer reads /proc/self/maps,
//     discovers libc and libparcagpucupti.so (loaded in TestMain), and attaches
//     the GPU USDT probes.
//  3. Verify GPU interpreter instance is attached, then simulate kernel launches
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

	enabledTracers, _ := tracertypes.Parse("")
	enabledTracers.Enable(tracertypes.CUDATracer)

	_, trc := testutils.StartTracer(ctx, t, enabledTracers, false)
	defer trc.Close()

	// Trigger initial process sync for our PID so the tracer discovers our
	// mappings and attaches the dlopen uprobe to libc.
	pid := libpf.PID(uint32(os.Getpid()))
	trc.ForceProcessPID(pid)

	// Wait until the process manager has processed our PID and attached
	// interpreter instances (the rtld instance attaches the dlopen uprobe
	// to libc as a side effect).
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

	// Set up ringbuf reader on the cupti_events map BEFORE the dlopen so we
	// don't miss any events.
	cuptiEventsMap := trc.GetEbpfMaps()["cupti_events"]
	require.NotNil(t, cuptiEventsMap, "cupti_events map not found")

	reader, err := ringbuf.NewReader(cuptiEventsMap)
	require.NoError(t, err, "ringbuf.NewReader failed")
	defer reader.Close()

	// libparcagpucupti.so was loaded in TestMain — ForceProcessPID will
	// discover it from /proc/self/maps and attach the GPU USDT probes.
	trc.ForceProcessPID(pid)

	// Wait until the GPU interpreter instance appears, confirming the USDT
	// probes were attached by the process manager.
	require.Eventually(t, func() bool {
		instances := trc.GetInterpretersForPID(pid)
		for _, inst := range instances {
			if _, ok := inst.(*gpu.Instance); ok {
				t.Log("GPU interpreter instance attached")
				return true
			}
		}
		t.Logf("waiting for GPU interpreter instance (%d interpreters so far)...", len(instances))
		trc.ForceProcessPID(pid)
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
