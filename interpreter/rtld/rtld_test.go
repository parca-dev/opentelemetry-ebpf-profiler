// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build amd64 && !integration

package rtld_test

import (
	"context"
	"testing"
	"time"
	"unsafe"

	"github.com/coreos/pkg/dlopen"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/testutils"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
)

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
