// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/times"
)

// HandleNvtxEvent converts a single cupti_events EVENT_TYPE_NVTX record into a
// language-neutral samples.NvtxEvent and forwards it via rep.ReportNvtxEvent.
// msg is the rest of the record after ev: the NUL-terminated message.
// rep may be nil (no NVTX reporter wired) — in that case the event is silently
// dropped; the BPF side already paid the ringbuf cost, but the trace pipeline
// is unaffected.
//
// Unlike PC samples we do *not* defer or correlate with kernel timing: NVTX
// emission is immediate. Any correlation against in-flight CUDA work is the
// downstream reporter's job (via the carried CorrelationID / DeviceID).
func HandleNvtxEvent(ev *CuptiNvtxEvent, msg []byte, rep reporter.NvtxReporter) {
	if rep == nil {
		return
	}
	// Transient: pfunsafe.ToString aliases the record's bytes; the
	// NvtxReporter implementation must copy if it retains beyond this call.
	message := pfunsafe.ToString(nullTerm(msg))

	out := &samples.NvtxEvent{
		// parcagpu stamps events with CLOCK_MONOTONIC, the same clock as
		// bpf_ktime_get_ns.
		TimeUnixNano:  times.KTime(ev.Data.TimestampNs).UnixNano(),
		PID:           ev.Pid,
		TID:           ev.Data.TID,
		CorrelationID: ev.Data.CorrelationID,
		DeviceID:      ev.Data.DeviceID,
		DomainID:      ev.Data.DomainID,
		Kind:          samples.NvtxKind(ev.Data.Kind),
		Color:         ev.Data.Color,
		Payload:       ev.Data.Payload,
		RangeID:       ev.Data.RangeID,
		Message:       message,
	}
	if err := rep.ReportNvtxEvent(out); err != nil {
		log.Debugf("[cuda] nvtx report dropped: %v", err)
	}
}

// HandleNvtxResourceName converts a single cupti_events EVENT_TYPE_NVTX_NAME
// record (one-off resource naming call) and forwards it via the NvtxReporter.
// rep may be nil; see HandleNvtxEvent for rationale.
func HandleNvtxResourceName(ev *CuptiNvtxNameEvent, rep reporter.NvtxReporter) {
	if rep == nil {
		return
	}
	name := pfunsafe.ToString(nullTerm(ev.Name[:]))
	out := &samples.NvtxResourceNameEvent{
		PID:  ev.Pid,
		Kind: samples.NvtxResourceKind(ev.Kind),
		ID:   ev.ID,
		Name: name,
	}
	if err := rep.ReportNvtxResourceName(out); err != nil {
		log.Debugf("[cuda] nvtx resource-name report dropped: %v", err)
	}
}
