// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"fmt"
	"sync"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

// seenLogRecords is how many (pid, time) pairs are kept to drop replays.
// parcagpu replays at most its last 64 records to a consumer that attaches.
const seenLogRecords = 4096

type logRecordKey struct {
	pid    uint32
	timeNs uint64
}

// logDedup remembers the most recent log records, oldest dropped first.
type logDedup struct {
	mu    sync.Mutex
	seen  map[logRecordKey]struct{}
	order []logRecordKey // ring, next slot at next % len
	next  int
}

func newLogDedup(n int) *logDedup {
	return &logDedup{seen: make(map[logRecordKey]struct{}, n), order: make([]logRecordKey, n)}
}

// add reports whether k is new, and remembers it.
func (d *logDedup) add(k logRecordKey) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.seen[k]; ok {
		return false
	}
	slot := d.next % len(d.order)
	if d.next >= len(d.order) {
		delete(d.seen, d.order[slot])
	}
	d.order[slot] = k
	d.seen[k] = struct{}{}
	d.next++
	return true
}

var shimLogs = newLogDedup(seenLogRecords)

// FormatLogEvent renders a parcagpu log record as one log line.
func FormatLogEvent(ev *CuptiLogEvent) string {
	msg := fmt.Sprintf("[parcagpu] pid=%d %s: %s", ev.Pid, nullTerm(ev.Component[:]),
		nullTerm(ev.Message[:]))
	if ev.Code != 0 {
		msg += fmt.Sprintf(" (code %d)", ev.Code)
	}
	return msg
}

// HandleLogEvent logs a record from parcagpu's log probe at its level. A
// record seen before is dropped: parcagpu replays the records logged before
// a consumer attached, and another consumer attaching (or an agent restart)
// replays them again. Returns whether the record was logged.
func HandleLogEvent(ev *CuptiLogEvent) bool {
	if !shimLogs.add(logRecordKey{pid: ev.Pid, timeNs: ev.TimeNs}) {
		return false
	}
	msg := FormatLogEvent(ev)
	switch {
	case ev.Level >= LogLevelError:
		log.Errorf("%s", msg)
	case ev.Level == LogLevelWarn:
		log.Warnf("%s", msg)
	case ev.Level == LogLevelInfo:
		log.Infof("%s", msg)
	default:
		log.Debugf("%s", msg)
	}
	return true
}
