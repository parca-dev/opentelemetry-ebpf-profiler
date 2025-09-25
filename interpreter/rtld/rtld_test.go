// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build amd64 && !integration

package rtld_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/coreos/pkg/dlopen"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/interpreter/rtld"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/testutils"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/util"
)

func TestLdsoRegexp(t *testing.T) {
	testCases := []struct {
		name     string
		expected bool
	}{
		// Standard glibc filenames
		{"ld-linux-x86-64.so.2", true},
		{"ld-linux-aarch64.so.1", true},
		{"ld-2.31.so", true},
		{"ld-2.35.so", true},

		// Alternative ld.so naming
		{"ld.so.1", true},
		{"ld.so.2", true},
		{"ld-linux.so.2", true},

		// musl libc
		{"ld-musl-x86_64.so.1", true},
		{"ld-musl-aarch64.so.1", true},

		// Invalid filenames
		{"libc.so.6", false},
		{"ld", false},
		{"ld-linux.so", false},       // missing version number
		{"ld-linux-x86-64.so", false}, // missing version number
		{"libm.so.6", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := rtld.LdsoRegexp.MatchString(tc.name)
			require.Equal(t, tc.expected, result, "Filename: %s", tc.name)
		})
	}
}

func TestIntegration(t *testing.T) {
	if !testutils.IsRoot() {
		t.Skip("This test requires root privileges")
	}

	// Create a context for the tracer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start the tracer with all tracers enabled
	traceCh, trc := testutils.StartTracer(ctx, t,
		tracertypes.AllTracers(),
		&testutils.MockReporter{},
		false)
	defer trc.Close()

	// Consume traces to prevent blocking
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-traceCh:
				// Discard traces
			}
		}
	}()

	// retry a few times to get the metric, our process has to be detected and
	// the rtld interpreter has to attach.
	require.Eventually(t, func() bool {
		// Get the initial metric value
		initialCount := getEBPFMetricValue(trc, metrics.IDRtldMapCompleteHits)
		t.Logf("Initial rtld:map_complete metric count: %d", initialCount)

		// Use dlopen to load a shared library
		// libm is a standard math library that's always present
		lib, err := dlopen.GetHandle([]string{
			"/lib/x86_64-linux-gnu/libm.so.6",
			"libm.so.6",
		})
		require.NoError(t, err, "Failed to open libm.so.6")
		defer lib.Close()

		// Get the metrics after dlopen
		finalCount := getEBPFMetricValue(trc, metrics.IDRtldMapCompleteHits)
		t.Logf("Final rtld:map_complete metric count: %d", finalCount)

		// Check that the metric was incremented
		return finalCount > initialCount
	}, 10*time.Second, 50*time.Millisecond)
}

func TestIntegrationPoller(t *testing.T) {
	// Get current process PID
	pid := libpf.PID(os.Getpid())

	// Create a notification channel for the test
	notifyCh := make(chan libpf.PID, 10)
	// Create a test trigger function
	triggerFunc := func(triggerPID libpf.PID) {
		t.Logf("Test trigger function called for PID %d", triggerPID)
	}
	rtld.SetTestNotifyChannelForTesting(notifyCh, triggerFunc)

	// Register our PID with the poller
	rtld.RegisterPIDForTesting(pid, triggerFunc)
	defer rtld.DeregisterPIDForTesting(pid, triggerFunc)

	// Wait a bit for the poller to get the initial hash
	time.Sleep(2 * time.Second)

	// Clear any initial notifications
	for {
		select {
		case <-notifyCh:
		default:
			goto done
		}
	}
done:

	// Use dlopen to load a shared library which should trigger a maps change
	var wg sync.WaitGroup
	var detectedChange bool

	// Start a goroutine to wait for the notification
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case detectedPID := <-notifyCh:
			require.Equal(t, pid, detectedPID, "Expected notification for our PID")
			detectedChange = true
		case <-time.After(5 * time.Second):
			t.Log("Timeout waiting for poller notification")
		}
	}()

	// Load a library to trigger maps change
	lib, err := dlopen.GetHandle([]string{
		"/lib/x86_64-linux-gnu/libm.so.6",
		"/usr/lib/x86_64-linux-gnu/libm.so.6",
		"libm.so.6",
	})
	require.NoError(t, err, "Failed to open libm.so.6")

	// Wait for the goroutine to complete
	wg.Wait()

	// Close the library
	lib.Close()

	require.True(t, detectedChange, "Poller should have detected the maps change from dlopen")
}

func TestIntegrationSingleShot(t *testing.T) {
	if !testutils.IsRoot() {
		t.Skip("This test requires root privileges")
	}

	// Override HasMultiUprobeSupport to force single-shot mode
	multiUProbeOverride := false
	util.SetTestOnlyMultiUprobeSupport(&multiUProbeOverride)
	defer util.SetTestOnlyMultiUprobeSupport(nil)

	// Create a context for the tracer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start the tracer with all tracers enabled
	traceCh, trc := testutils.StartTracer(ctx, t,
		tracertypes.AllTracers(),
		&testutils.MockReporter{},
		false)
	defer trc.Close()

	// Consume traces to prevent blocking
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-traceCh:
				// Discard traces
			}
		}
	}()

	// retry a few times to get the metric, our process has to be detected and
	// the rtld interpreter has to attach.
	require.Eventually(t, func() bool {
		// Get the initial metric value
		initialCount := getEBPFMetricValue(trc, metrics.IDRtldMapCompleteHits)
		//t.Logf("Initial rtld:map_complete metric count: %d", initialCount)

		// Use dlopen to load a shared library
		// libm is a standard math library that's always present
		lib, err := dlopen.GetHandle([]string{
			"/lib/x86_64-linux-gnu/libm.so.6",
			"libm.so.6",
		})
		require.NoError(t, err, "Failed to open libm.so.6")
		defer lib.Close()

		// Get the metrics after dlopen
		finalCount := getEBPFMetricValue(trc, metrics.IDRtldMapCompleteHits)
		//t.Logf("Final rtld:map_complete metric count: %d", finalCount)

		// Check that the metric was incremented
		return finalCount > initialCount
	}, 10*time.Second, 50*time.Millisecond)
}

func getEBPFMetricValue(trc *tracer.Tracer, metricID metrics.MetricID) uint64 {
	// Access the eBPF maps directly using the public method
	ebpfMaps := trc.GetEbpfMaps()
	metricsMap, ok := ebpfMaps["metrics"]
	if !ok {
		return 0
	}

	// Find the eBPF metric ID that corresponds to our metrics.MetricID
	var ebpfMetricID uint32
	for ebpfID, id := range support.MetricsTranslation {
		if id == metricID {
			ebpfMetricID = uint32(ebpfID)
			break
		}
	}

	// Read the per-CPU values
	var perCPUValues []uint64
	if err := metricsMap.Lookup(unsafe.Pointer(&ebpfMetricID), &perCPUValues); err != nil {
		return 0
	}

	// Sum all per-CPU values
	var total uint64
	for _, val := range perCPUValues {
		total += val
	}
	return total
}
