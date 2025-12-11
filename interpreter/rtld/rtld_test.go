// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rtld_test

import (
	"context"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/coreos/pkg/dlopen"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/testutils"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/util"
)

func TestIntegration(t *testing.T) {
	if !testutils.IsRoot() {
		t.Skip("This test requires root privileges")
	}

	// Enable debug logging for CI debugging
	if os.Getenv("DEBUG_TEST") != "" {
		log.SetLevel(log.DebugLevel)
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
	// the dlopen uprobe has to attach.
	require.Eventually(t, func() bool {
		// Get the initial metric value
		initialCount := getEBPFMetricValue(trc, metrics.IDDlopenUprobeHits)
		t.Logf("Initial dlopen uprobe metric count: %d", initialCount)

		// Use dlopen to load a shared library
		// libm is a standard math library that's always present
		lib, err := dlopen.GetHandle([]string{
			"/lib/x86_64-linux-gnu/libm.so.6",
			"libm.so.6",
		})
		require.NoError(t, err, "Failed to open libm.so.6")
		defer lib.Close()

		// Get the metrics after dlopen
		finalCount := getEBPFMetricValue(trc, metrics.IDDlopenUprobeHits)
		t.Logf("Final dlopen uprobe metric count: %d", finalCount)

		// Check that the metric was incremented
		return finalCount > initialCount
	}, 5*time.Minute, 100*time.Millisecond)
}

func TestIntegrationSingleShot(t *testing.T) {
	if !testutils.IsRoot() {
		t.Skip("This test requires root privileges")
	}

	// Enable debug logging for CI debugging
	if os.Getenv("DEBUG_TEST") != "" {
		log.SetLevel(log.DebugLevel)
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
	// the dlopen uprobe has to attach.
	require.Eventually(t, func() bool {
		// Get the initial metric value
		initialCount := getEBPFMetricValue(trc, metrics.IDDlopenUprobeHits)
		t.Logf("Initial dlopen uprobe metric count: %d", initialCount)

		// Use dlopen to load a shared library
		// libm is a standard math library that's always present
		lib, err := dlopen.GetHandle([]string{
			"/lib/x86_64-linux-gnu/libm.so.6",
			"libm.so.6",
		})
		require.NoError(t, err, "Failed to open libm.so.6")
		defer lib.Close()

		// Get the metrics after dlopen
		finalCount := getEBPFMetricValue(trc, metrics.IDDlopenUprobeHits)
		t.Logf("Final dlopen uprobe metric count: %d", finalCount)

		// Check that the metric was incremented
		return finalCount > initialCount
	}, 5*time.Minute, 100*time.Millisecond)
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
