package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"bytes"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
)

// stallReasonMaps stores per-PID stall reason name tables.
// Key: uint32 PID, Value: []string (indexed by stall reason index).
var stallReasonMaps sync.Map

// StoreStallReasonMap caches a stall reason name table for a given PID.
func StoreStallReasonMap(pid uint32, names []string) {
	stallReasonMaps.Store(pid, names)
}

// HandleStallReasonMap processes a single EVENT_TYPE_STALL_REASON_MAP event
// from the cupti_events ringbuf, extracting up to MAX_STALL_REASONS null-
// terminated names and caching them keyed by PID for later use by PC sample
// processing.
func HandleStallReasonMap(ev *CuptiStallReasonMapEvent) {
	count := ev.Count
	if count > uint32(len(ev.Names)) {
		count = uint32(len(ev.Names))
	}
	names := make([]string, count)
	for i := uint32(0); i < count; i++ {
		row := ev.Names[i][:]
		if idx := bytes.IndexByte(row, 0); idx >= 0 {
			row = row[:idx]
		}
		names[i] = string(row)
	}
	StoreStallReasonMap(ev.Pid, names)
}

// LookupStallReason returns the human-readable stall reason name for a given
// PID and stall reason index. Returns a numeric fallback if the index is out
// of range or the PID has no stall reason map.
func LookupStallReason(pid uint32, index uint32) string {
	v, ok := stallReasonMaps.Load(pid)
	if !ok {
		log.Warnf("[cuda] stall reason map not found for pid %d (index %d)", pid, index)
		return fmt.Sprintf("stall_reason_%d", index)
	}
	names := v.([]string)
	if int(index) >= len(names) || names[index] == "" {
		log.Warnf("[cuda] stall reason index %d out of range for pid %d (len=%d)", index, pid, len(names))
		return fmt.Sprintf("stall_reason_%d", index)
	}
	return names[index]
}

// DeleteStallReasonMap removes the stall reason map for a given PID.
func DeleteStallReasonMap(pid uint32) {
	stallReasonMaps.Delete(pid)
}
