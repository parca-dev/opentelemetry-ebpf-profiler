// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/ebpf-profiler/libpf"
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
