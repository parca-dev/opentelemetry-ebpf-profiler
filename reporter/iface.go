// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"context"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// Reporter is the top-level interface implemented by a full reporter.
type Reporter interface {
	TraceReporter

	// Start starts the reporter in the background.
	//
	// If the reporter needs to perform a long-running starting operation then it
	// is recommended that Start() returns quickly and the long-running operation
	// is performed in the background.
	Start(context.Context) error

	// Stop triggers a graceful shutdown of the reporter.
	Stop()
}

type TraceReporter interface {
	// ReportTraceEvent accepts a trace event (trace metadata with frames)
	// and enqueues it for reporting to the backend.
	// If handling the trace event fails it returns an error.
	ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error
}

// NvtxReporter is an optional sink for NVTX annotations (ranges, marks,
// resource names) from the CUDA interpreter. Events are delivered raw and in
// per-thread order; turning ranges into spans, logs or anything else is the
// implementation's job. Reporters that don't consume NVTX simply don't
// implement this; the caller checks for the interface and skips emission.
type NvtxReporter interface {
	// ReportNvtxEvent hands over a single NVTX event. Returning an error means
	// the event could not be accepted (e.g. backpressure); it is dropped.
	ReportNvtxEvent(ev *samples.NvtxEvent) error

	// ReportNvtxResourceName hands over a resource-name announcement.
	// Announcements are low-rate and may repeat; the consumer is expected to
	// keep its own cache and not require dedup from the caller.
	ReportNvtxResourceName(ev *samples.NvtxResourceNameEvent) error
}

type ExecutableMetadata struct {
	// MappingFile is the reference to mapping file data.
	MappingFile libpf.FrameMappingFile

	// Process is the interface to the process holding the file.
	Process process.Process

	// Mapping is the process.RawMapping file. Process.OpenMappingFile can be used
	// to open the file if needed.
	Mapping *process.RawMapping

	// DebuglinkFileName is the path to the matching debug file
	// from the .gnu.debuglink, if any. The caller should
	// verify that the file in question matches the GnuBuildID of this executable.
	DebuglinkFileName string
}

// ExecutableReporter is an optional interface to allow uploading files. There is
// no implementation in opentelemetry-ebpf-profiler for this, but it is kept to
// support this functionality in other (non-tree) protocol implementations.
type ExecutableReporter interface {
	ReportExecutable(args *ExecutableMetadata)
}
