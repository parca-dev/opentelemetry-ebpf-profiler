// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

func pcMeta(pid uint32, origin *PCSampleOrigin) *samples.TraceEventMeta {
	return &samples.TraceEventMeta{PID: libpf.PID(pid), OriginData: origin}
}

func TestGpuConfigPerDevice(t *testing.T) {
	const pid = 9001
	t.Cleanup(func() { DeleteGpuConfigs(pid) })

	// Two GPUs with different clocks and factors.
	HandleGpuConfigEvent(&CuptiGpuConfigEvent{Pid: pid, DeviceID: 0,
		SamplingFactor: 20, ClockKHz: 1_000_000, SMCount: 48})
	HandleGpuConfigEvent(&CuptiGpuConfigEvent{Pid: pid, DeviceID: 1,
		SamplingFactor: 18, ClockKHz: 2_000_000, SMCount: 132})

	cfg0, ok := LoadGpuConfig(pid, 0)
	require.True(t, ok)
	cfg1, ok := LoadGpuConfig(pid, 1)
	require.True(t, ok)
	assert.Equal(t, uint32(20), cfg0.SamplingFactor)
	assert.Equal(t, uint32(18), cfg1.SamplingFactor)
	_, ok = LoadGpuConfig(pid, 2)
	assert.False(t, ok)

	// 2^20 cycles at 1 GHz; 2^18 cycles at 2 GHz.
	assert.Equal(t, int64(1<<20), PCSampleNsPerSample(
		pcMeta(pid, &PCSampleOrigin{DeviceID: 0, HasDevice: true})))
	assert.Equal(t, int64(1<<17), PCSampleNsPerSample(
		pcMeta(pid, &PCSampleOrigin{DeviceID: 1, HasDevice: true})))
	assert.Zero(t, PCSampleNsPerSample(
		pcMeta(pid, &PCSampleOrigin{DeviceID: 2, HasDevice: true})))

	// Without a device the pid's config is ambiguous.
	assert.Zero(t, PCSampleNsPerSample(pcMeta(pid, &PCSampleOrigin{})))
	assert.Zero(t, PCSampleNsPerSample(pcMeta(pid, nil)))

	// A live factor change replaces only that device's config.
	HandleGpuConfigEvent(&CuptiGpuConfigEvent{Pid: pid, DeviceID: 0,
		SamplingFactor: 15, ClockKHz: 1_000_000, SMCount: 48})
	assert.Equal(t, int64(1<<15), PCSampleNsPerSample(
		pcMeta(pid, &PCSampleOrigin{DeviceID: 0, HasDevice: true})))
	assert.Equal(t, int64(1<<17), PCSampleNsPerSample(
		pcMeta(pid, &PCSampleOrigin{DeviceID: 1, HasDevice: true})))

	DeleteGpuConfigs(pid)
	_, ok = LoadGpuConfig(pid, 0)
	assert.False(t, ok)
}

func TestGpuConfigWithoutSampleDevice(t *testing.T) {
	const pid = 9002
	t.Cleanup(func() { DeleteGpuConfigs(pid) })

	assert.Zero(t, PCSampleNsPerSample(pcMeta(pid, &PCSampleOrigin{})))

	// An older parcagpu's samples carry no device: a single-GPU process's
	// config still applies.
	StoreGpuConfig(pid, &GpuConfig{DeviceID: 3, SamplingFactor: 10, ClockKHz: 1_000_000})
	assert.Equal(t, int64(1<<10), PCSampleNsPerSample(pcMeta(pid, &PCSampleOrigin{})))
	assert.Equal(t, int64(1<<10), PCSampleNsPerSample(pcMeta(pid, nil)))
}
