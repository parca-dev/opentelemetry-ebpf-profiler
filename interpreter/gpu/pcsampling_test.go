// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu

import (
	"context"
	"maps"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// TestBuildGpuPCMetaCopiesProcessIdentity checks that a gpupc sample inherits
// the CPU trace's metadata (process identity, resource, enricher output and
// span) and overrides only its own type and value.
// Reporters key resources on PID/executable/container and keep the latest
// resource snapshot, so a missing ResourceAttrs would clear the process's
// service.name for the whole reporting interval.
func TestBuildGpuPCMetaCopiesProcessIdentity(t *testing.T) {
	cpuMeta := &samples.TraceEventMeta{
		Timestamp:      12345,
		PID:            42,
		TID:            43,
		CPU:            3,
		Comm:           libpf.NewCommFromString("python3"),
		ExecutablePath: libpf.Intern("/usr/bin/python3"),
		ContainerID:    libpf.Intern("container-a"),
		EnvVars:        map[libpf.String]libpf.String{libpf.Intern("FOO"): libpf.Intern("bar")},
		ResourceAttrs:  attribute.NewSet(attribute.String("service.name", "vllm")),
		ExtraMeta:      map[libpf.String]string{libpf.Intern("k"): "v"},
		SpanID:         libpf.SpanID{1, 2, 3, 4, 5, 6, 7, 8},
		TraceID:        libpf.TraceID{9},
		ProfileType:    ProfileTypeCuda,
		ContextValues:  []uint64{99, 98},
		OriginData:     "cuda-only",
	}

	meta := buildGpuPCMeta(&SymbolizedCudaTrace{Meta: cpuMeta}, 42, 7)

	assert.Equal(t, ProfileTypeGpuPC, meta.ProfileType)
	assert.Equal(t, []uint64{7}, meta.ContextValues)
	assert.Equal(t, cpuMeta.Timestamp, meta.Timestamp)
	assert.Equal(t, cpuMeta.PID, meta.PID)
	assert.Equal(t, cpuMeta.TID, meta.TID)
	assert.Equal(t, cpuMeta.CPU, meta.CPU)
	assert.Equal(t, cpuMeta.Comm, meta.Comm)
	assert.Equal(t, cpuMeta.ExecutablePath, meta.ExecutablePath)
	assert.Equal(t, cpuMeta.ContainerID, meta.ContainerID)
	assert.Equal(t, cpuMeta.EnvVars, meta.EnvVars)
	assert.True(t, cpuMeta.ResourceAttrs.Equals(&meta.ResourceAttrs),
		"ResourceAttrs not copied: got %v", meta.ResourceAttrs.ToSlice())
	assert.Equal(t, cpuMeta.ExtraMeta, meta.ExtraMeta)
	assert.Equal(t, cpuMeta.SpanID, meta.SpanID)
	assert.Equal(t, cpuMeta.TraceID, meta.TraceID)
	assert.Nil(t, meta.OriginData)

	// The CPU trace's meta is shared with its kernel timings; leave it alone.
	assert.Equal(t, ProfileTypeCuda, cpuMeta.ProfileType)
	assert.Equal(t, []uint64{99, 98}, cpuMeta.ContextValues)
	assert.Equal(t, "cuda-only", cpuMeta.OriginData)
}

func TestBuildGpuPCMetaWithoutCPUTrace(t *testing.T) {
	meta := buildGpuPCMeta(nil, 42, 7)
	assert.Equal(t, libpf.PID(42), meta.PID)
	assert.Equal(t, ProfileTypeGpuPC, meta.ProfileType)
	assert.Equal(t, []uint64{7}, meta.ContextValues)
	assert.NotZero(t, meta.Timestamp)
}

func TestPCSampleCustomLabelTraceLink(t *testing.T) {
	const pid = libpf.PID(520)
	RegisterTestFixer(pid)
	t.Cleanup(func() { UnregisterTestFixer(pid) })
	const crc = uint64(0xabcdef)
	StoreCubin(&CubinInfo{CRC: crc, FileID: libpf.NewFileID(crc, 0)})
	t.Cleanup(func() { cubinCache.Delete(crc) })

	trace := &libpf.Trace{CustomLabels: map[libpf.String]libpf.String{
		libpf.Intern("otel.trace_id"):     libpf.Intern("00112233445566778899aabbccddeeff"),
		libpf.Intern("otel.span_id"):      libpf.Intern("1020304050607080"),
		libpf.Intern("tenant"):            libpf.Intern("acme"),
		libpf.Intern("cuda_stall_reason"): libpf.Intern("launch-value"),
	}}
	trace.Frames.Append(&libpf.Frame{Type: libpf.CUDAKernelFrame, AddressOrLineno: 42})
	originalLabels := maps.Clone(trace.CustomLabels)
	require.Empty(t, InterceptTrace(trace, &samples.TraceEventMeta{
		PID: pid, Timestamp: libpf.UnixTime64(time.Now().UnixNano()), ProfileType: ProfileTypeCuda,
	}))

	exported := make(chan pprofile.Profiles, 1)
	next, err := xconsumer.NewProfiles(func(_ context.Context, profiles pprofile.Profiles) error {
		exported <- profiles
		return nil
	})
	require.NoError(t, err)
	r, err := reporter.NewCollector(&reporter.Config{ReportInterval: 10 * time.Millisecond}, next)
	require.NoError(t, err)

	ev := &CuptiPCSampleEvent{Pid: uint32(pid), CorrelationID: 42}
	ev.Data.CubinCRC = crc
	ev.Data.StallReasonCount = 2
	ev.StallReasons[0].Samples = 3
	ev.StallReasons[1].Samples = 7
	ev.StallReasons[1].Index = 1
	HandlePCSample(ev, r)
	require.NoError(t, r.Start(t.Context()))
	t.Cleanup(r.Stop)

	var profiles pprofile.Profiles
	select {
	case profiles = <-exported:
	case <-time.After(5 * time.Second):
		t.Fatal("GPU PC samples were not exported")
	}
	require.Equal(t, 2, profiles.SampleCount())
	dict := profiles.Dictionary()
	require.Equal(t, 2, dict.LinkTable().Len(), "both stall reasons share the launching span")
	profileSamples := profiles.ResourceProfiles().At(0).ScopeProfiles().At(0).Profiles().At(0).Samples()
	for i := range profileSamples.Len() {
		sample := profileSamples.At(i)
		require.Positive(t, sample.LinkIndex())
		link := dict.LinkTable().At(int(sample.LinkIndex()))
		require.Equal(t, pcommon.TraceID{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, link.TraceID())
		require.Equal(t, pcommon.SpanID{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}, link.SpanID())
		attrs := map[string]string{}
		indices := sample.AttributeIndices()
		for j := range indices.Len() {
			a := dict.AttributeTable().At(int(indices.At(j)))
			attrs[dict.StringTable().At(int(a.KeyStrindex()))] = a.Value().Str()
		}
		require.Equal(t, "acme", attrs["process.context.label.tenant"])
		require.NotEmpty(t, attrs["process.context.label.cuda_stall_reason"])
		require.NotEqual(t, "launch-value", attrs["process.context.label.cuda_stall_reason"])
	}
	require.Equal(t, originalLabels, trace.CustomLabels, "GPU labels must not mutate the CPU trace")
}
