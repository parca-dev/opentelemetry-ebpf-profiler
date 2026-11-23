// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

// Layout of struct log_event in cuda.ebpf.c.
func TestLogEventLayout(t *testing.T) {
	var ev CuptiLogEvent
	assert.Equal(t, uintptr(312), unsafe.Sizeof(ev))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(ev.TimeNs))
	assert.Equal(t, uintptr(24), unsafe.Offsetof(ev.Component))
	assert.Equal(t, uintptr(56), unsafe.Offsetof(ev.Message))
}

func logEvent(pid uint32, timeNs uint64, level uint32, code int32, comp, msg string) *CuptiLogEvent {
	ev := &CuptiLogEvent{EventType: EventTypeLog, Level: level, Code: code, Pid: pid,
		TimeNs: timeNs}
	copy(ev.Component[:], comp)
	copy(ev.Message[:], msg)
	return ev
}

func TestFormatLogEvent(t *testing.T) {
	assert.Equal(t, "[parcagpu] pid=7 cupti: parcagpu v1 inactive: cuptiSubscribe failed (code 39)",
		FormatLogEvent(logEvent(7, 1, LogLevelError, 39, "cupti",
			"parcagpu v1 inactive: cuptiSubscribe failed")))
	assert.Equal(t, "[parcagpu] pid=7 kernel_stats: recording every kernel",
		FormatLogEvent(logEvent(7, 1, LogLevelInfo, 0, "kernel_stats",
			"recording every kernel")))
}

func TestHandleLogEventDropsReplays(t *testing.T) {
	shimLogs = newLogDedup(seenLogRecords)
	ev := logEvent(100, 1_000, LogLevelWarn, 0, "env_config", "unrecognized env var")
	assert.True(t, HandleLogEvent(ev))
	assert.False(t, HandleLogEvent(ev), "replayed record")
	assert.True(t, HandleLogEvent(logEvent(101, 1_000, LogLevelWarn, 0, "env_config",
		"unrecognized env var")), "same time, other process")
	assert.True(t, HandleLogEvent(logEvent(100, 1_001, LogLevelInfo, 0, "cupti", "active")))
}

func TestLogDedupForgetsOldest(t *testing.T) {
	d := newLogDedup(2)
	assert.True(t, d.add(logRecordKey{1, 1}))
	assert.True(t, d.add(logRecordKey{1, 2}))
	assert.True(t, d.add(logRecordKey{1, 3})) // forgets {1, 1}
	assert.False(t, d.add(logRecordKey{1, 3}))
	assert.False(t, d.add(logRecordKey{1, 2}))
	assert.True(t, d.add(logRecordKey{1, 1}))
}
