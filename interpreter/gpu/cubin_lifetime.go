// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"sync"
	"time"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

// cubinUnloadGrace is how long a cubin's metadata and code outlive the last
// process holding it. Samples taken before the unload can still be in
// flight: a PC sample waits up to maxEntryAge in pendingPCSamples for its
// correlation trace (swept every ~2 s), parcagpu can drain CUPTI's buffer
// after the unload probe fires, and the agent handles samples on their own
// goroutines. Each of those looks the cubin up by CRC when it is emitted.
const cubinUnloadGrace = 2 * maxEntryAge

// cubinImageLoc is where a process holds a cubin's image.
type cubinImageLoc struct {
	ptr, size uint64
}

// cubinHolders tracks which processes have a cubin CRC loaded. CubinInfo and
// the code cache are keyed by CRC alone and shared by every such process.
type cubinHolders struct {
	pids map[uint32]cubinImageLoc
	// releasedAt is when the last holder went away; zero while held.
	releasedAt time.Time
}

// cubinLifetimes is only populated through TrackCubinLoad. Cubins it doesn't
// know (a consumer that never calls TrackCubinLoad) are kept forever, as
// before cubin_unloaded was consumed. Lock order: cubinLifetimes, then
// cubinCodeCache.
var cubinLifetimes = struct {
	sync.Mutex
	crcs map[uint64]*cubinHolders
}{crcs: make(map[uint64]*cubinHolders)}

// TrackCubinLoad records that ev.Pid holds the cubin, which keeps its
// metadata and cached code alive until every holder unloads it or exits.
// Call it synchronously from the goroutine reading cupti_events, in ringbuf
// order with HandleCubinUnloadedEvent, before handing the load to a
// goroutine: the ringbuf orders one process's load before its unload, but
// the asynchronous load handling does not. Replays of a loaded cubin are
// harmless. HandleCubinEvent calls it itself.
func TrackCubinLoad(ev *CuptiCubinEvent) {
	cubinLifetimes.Lock()
	defer cubinLifetimes.Unlock()
	h := cubinLifetimes.crcs[ev.CubinCRC]
	if h == nil {
		h = &cubinHolders{pids: make(map[uint32]cubinImageLoc)}
		cubinLifetimes.crcs[ev.CubinCRC] = h
	}
	h.pids[ev.Pid] = cubinImageLoc{ptr: ev.CubinPtr, size: ev.CubinSize}
	h.releasedAt = time.Time{}
}

// HandleCubinUnloadedEvent handles EVENT_TYPE_CUBIN_UNLOADED: ev.Pid unloaded
// its last module with this CRC. Call it synchronously, like TrackCubinLoad.
// What the agent keeps for the CRC is dropped only once no process holds it
// and cubinUnloadGrace has passed, so samples still in flight resolve.
func HandleCubinUnloadedEvent(ev *CuptiCubinUnloadedEvent) {
	releaseCubin(ev.Pid, ev.CubinCRC, time.Now())
}

func releaseCubin(pid uint32, crc uint64, now time.Time) {
	cubinLifetimes.Lock()
	defer cubinLifetimes.Unlock()
	releaseCubinLocked(pid, crc, now)
}

// releaseProcessCubins releases every cubin pid holds, when it exits or its
// parcagpu library goes away. Most processes exit without unloading modules.
func releaseProcessCubins(pid uint32, now time.Time) {
	cubinLifetimes.Lock()
	defer cubinLifetimes.Unlock()
	for crc, h := range cubinLifetimes.crcs {
		if _, ok := h.pids[pid]; ok {
			releaseCubinLocked(pid, crc, now)
		}
	}
}

// releaseCubinLocked requires cubinLifetimes' lock.
func releaseCubinLocked(pid uint32, crc uint64, now time.Time) {
	h := cubinLifetimes.crcs[crc]
	var next cubinImageLoc
	var nextPid uint32
	haveNext := false
	if h != nil {
		delete(h.pids, pid)
		for p, loc := range h.pids {
			nextPid, next, haveNext = p, loc, true
			break
		}
		if len(h.pids) == 0 && h.releasedAt.IsZero() {
			h.releasedAt = now
		}
	}
	// The unloaded image's memory may be freed or reused, so stop rereading
	// evicted code from it. Another holder's copy has the same CRC; the
	// reread validates it against the original hash anyway.
	cubinCodeCache.Lock()
	defer cubinCodeCache.Unlock()
	origin := cubinCodeCache.origins[crc]
	if origin == nil || origin.pid != pid {
		return
	}
	if !haveNext || next.size != origin.size {
		delete(cubinCodeCache.origins, crc)
		return
	}
	cubinCodeCache.origins[crc] = &cubinOrigin{pid: nextPid, ptr: next.ptr,
		size: next.size, hash: origin.hash, lastRefill: origin.lastRefill}
}

// sweepUnloadedCubins drops the metadata, cached code and image origin of
// every cubin no process has held for cubinUnloadGrace, and returns how many.
// A file-backed source closes its descriptor once unreachable; queued uploads
// keep what they hold.
func sweepUnloadedCubins(now time.Time) int {
	cubinLifetimes.Lock()
	defer cubinLifetimes.Unlock()
	dropped := 0
	for crc, h := range cubinLifetimes.crcs {
		if len(h.pids) > 0 || now.Sub(h.releasedAt) < cubinUnloadGrace {
			continue
		}
		delete(cubinLifetimes.crcs, crc)
		cubinCache.Delete(crc)
		cubinCodeCache.Lock()
		if e, ok := cubinCodeCache.entries[crc]; ok {
			removeCubinCode(e)
		}
		delete(cubinCodeCache.origins, crc)
		cubinCodeCache.Unlock()
		dropped++
		log.Debugf("[cuda] dropped unloaded cubin 0x%x", crc)
	}
	return dropped
}
