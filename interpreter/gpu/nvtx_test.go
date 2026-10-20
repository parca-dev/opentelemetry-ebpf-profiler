// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/times"
)

type recordingNvtxReporter struct {
	events []samples.NvtxEvent
	names  []samples.NvtxResourceNameEvent
}

func (r *recordingNvtxReporter) ReportNvtxEvent(ev *samples.NvtxEvent) error {
	r.events = append(r.events, *ev)
	return nil
}

func (r *recordingNvtxReporter) ReportNvtxResourceName(ev *samples.NvtxResourceNameEvent) error {
	r.names = append(r.names, *ev)
	return nil
}

// TestHandleNvtxEventWallClock checks that the producer's CLOCK_MONOTONIC
// timestamp is converted to wall clock rather than passed through (which
// would put every event a few days after the Unix epoch).
func TestHandleNvtxEventWallClock(t *testing.T) {
	times.StartRealtimeSync(context.Background(), 0)

	var ev CuptiNvtxEvent
	ev.Pid = 42
	ev.Data.TID = 7
	ev.Data.DomainID = 1
	ev.Data.Kind = uint16(samples.NvtxKindRangePush)
	ev.Data.TimestampNs = uint64(times.GetKTime())
	copy(ev.Message[:], "forward_step")

	rep := &recordingNvtxReporter{}
	HandleNvtxEvent(&ev, rep)

	require.Len(t, rep.events, 1)
	got := rep.events[0]
	assert.WithinDuration(t, time.Now(), time.Unix(0, got.TimeUnixNano), time.Second)
	assert.Equal(t, uint32(42), got.PID)
	assert.Equal(t, uint32(7), got.TID)
	assert.Equal(t, uint32(1), got.DomainID)
	assert.Equal(t, samples.NvtxKindRangePush, got.Kind)
	assert.Equal(t, "forward_step", got.Message)
}

func TestHandleNvtxResourceNameDomain(t *testing.T) {
	var ev CuptiNvtxNameEvent
	ev.Pid = 42
	ev.Kind = uint32(samples.NvtxResourceDomain)
	ev.ID = 1
	copy(ev.Name[:], "TensorRT-LLM")

	rep := &recordingNvtxReporter{}
	HandleNvtxResourceName(&ev, rep)

	require.Len(t, rep.names, 1)
	assert.Equal(t, samples.NvtxResourceNameEvent{
		PID: 42, Kind: samples.NvtxResourceDomain, ID: 1, Name: "TensorRT-LLM",
	}, rep.names[0])
}
