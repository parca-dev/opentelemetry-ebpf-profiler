// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"container/list"
	"crypto/sha256"
	"sync"
	"time"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

// DefaultCubinCodeCacheSize disables memory-only mnemonic caching by default.
// File-backed sources, identity metadata and queued uploads are unaffected.
const DefaultCubinCodeCacheSize uint64 = 0

// cubinRefillInterval bounds how often one evicted image is reread after a
// sample misses it, so an oversubscribed cache cannot reread on every sample.
const cubinRefillInterval = time.Second

type cubinCodeEntry struct {
	crc   uint64
	image []byte
}

// cubinOrigin locates a memory-only image in the process that loaded it, so a
// sample can reread it after eviction. The hash rejects memory that an
// unloaded module or a recycled PID has reused. Fields other than lastRefill
// and refilling are immutable; a new notification replaces the origin.
type cubinOrigin struct {
	pid        uint32
	ptr, size  uint64
	hash       [sha256.Size]byte
	lastRefill time.Time
	refilling  bool
}

// Instruction reads copy just 16 bytes while holding the lock. Neither metadata
// nor readers can pin an evicted image in memory after the lock is released.
var cubinCodeCache = struct {
	sync.Mutex
	limit   uint64
	used    uint64
	entries map[uint64]*list.Element
	origins map[uint64]*cubinOrigin // Recorded only while the cache is enabled.
	order   list.List               // Most recently sampled at the front.
}{
	limit:   DefaultCubinCodeCacheSize,
	entries: make(map[uint64]*list.Element),
	origins: make(map[uint64]*cubinOrigin),
}

// SetCubinCodeCacheSize changes the byte budget, evicting old images if needed.
// Zero disables in-memory mnemonic enrichment, not samples or debug-file uploads,
// and forgets image origins, so cubins notified afterwards count as new.
func SetCubinCodeCacheSize(size uint64) {
	cubinCodeCache.Lock()
	defer cubinCodeCache.Unlock()
	cubinCodeCache.limit = size
	for cubinCodeCache.used > size {
		removeCubinCode(cubinCodeCache.order.Back())
	}
	if size == 0 {
		clear(cubinCodeCache.origins)
	}
}

// removeCubinCode requires cubinCodeCache's lock.
func removeCubinCode(e *list.Element) {
	entry := e.Value.(cubinCodeEntry)
	cubinCodeCache.used -= uint64(cap(entry.image))
	delete(cubinCodeCache.entries, entry.crc)
	cubinCodeCache.order.Remove(e)
}

// admitCubinCode requires cubinCodeCache's lock. An image larger than the
// budget is skipped without evicting other cubins.
func admitCubinCode(crc uint64, image []byte) {
	if _, ok := cubinCodeCache.entries[crc]; ok {
		return
	}
	// Charge the backing buffer, including any unused tail capacity.
	size := uint64(cap(image))
	if len(image) == 0 || size > cubinCodeCache.limit {
		return
	}
	for cubinCodeCache.used > cubinCodeCache.limit-size {
		removeCubinCode(cubinCodeCache.order.Back())
	}
	e := cubinCodeCache.order.PushFront(cubinCodeEntry{crc: crc, image: image})
	cubinCodeCache.entries[crc] = e
	cubinCodeCache.used += size
}

// CacheCubinCode records where a memory-only image lives in process pid at ptr
// and admits it the first time its CRC is seen. The caller must not modify
// image afterwards. Repeated notifications, such as the shim's periodic
// replays, update the origin but neither readmit an evicted image nor refresh
// recency: samples that miss reread it, so the cache keeps what is sampled
// rather than what loaded last. File-backed cubins need no copy.
func CacheCubinCode(info *CubinInfo, pid uint32, ptr uint64, image []byte) {
	cubinCodeCache.Lock()
	enabled := cubinCodeCache.limit > 0
	if info.Source != nil {
		if e, ok := cubinCodeCache.entries[info.CRC]; ok {
			removeCubinCode(e)
		}
		delete(cubinCodeCache.origins, info.CRC)
	}
	cubinCodeCache.Unlock()
	if info.Source != nil || !enabled || len(image) == 0 {
		return
	}
	hash := sha256.Sum256(image) // Outside the lock; images can be large.

	cubinCodeCache.Lock()
	defer cubinCodeCache.Unlock()
	if cubinCodeCache.limit == 0 {
		return
	}
	origin := &cubinOrigin{pid: pid, ptr: ptr, size: uint64(len(image)), hash: hash}
	old, known := cubinCodeCache.origins[info.CRC]
	if known {
		origin.lastRefill = old.lastRefill
	}
	cubinCodeCache.origins[info.CRC] = origin
	if !known {
		admitCubinCode(info.CRC, image)
	}
}

// refillCubinCode rereads an evicted image in the background after a sample
// missed it. That sample has no mnemonic; later ones do once it is admitted.
func refillCubinCode(crc uint64) {
	cubinCodeCache.Lock()
	defer cubinCodeCache.Unlock()
	origin := cubinCodeCache.origins[crc]
	if origin == nil || origin.refilling || origin.size > cubinCodeCache.limit ||
		time.Since(origin.lastRefill) < cubinRefillInterval {
		return
	}
	if _, ok := cubinCodeCache.entries[crc]; ok {
		return
	}
	origin.refilling, origin.lastRefill = true, time.Now()
	go func() {
		image, err := ReadCubinFromProcess(origin.pid, origin.ptr, origin.size)
		valid := err == nil && uint64(len(image)) == origin.size &&
			sha256.Sum256(image) == origin.hash
		cubinCodeCache.Lock()
		defer cubinCodeCache.Unlock()
		origin.refilling = false
		if !valid {
			log.Debugf("[cuda] cubin 0x%x no longer readable from pid %d: %v", crc, origin.pid, err)
			return
		}
		// A newer notification may have moved the image; it refills on its own.
		if cubinCodeCache.origins[crc] == origin {
			admitCubinCode(crc, image)
		}
	}()
}

func hasCubinCode(crc uint64) bool {
	cubinCodeCache.Lock()
	defer cubinCodeCache.Unlock()
	_, ok := cubinCodeCache.entries[crc]
	return ok
}

// readCubinInstruction copies one instruction from a resident image and marks
// it recently sampled. A miss schedules a reread of the evicted image.
func readCubinInstruction(crc, offset uint64, instruction *[16]byte) bool {
	cubinCodeCache.Lock()
	e, ok := cubinCodeCache.entries[crc]
	if !ok {
		cubinCodeCache.Unlock()
		refillCubinCode(crc)
		return false
	}
	defer cubinCodeCache.Unlock()
	image := e.Value.(cubinCodeEntry).image
	if offset > uint64(len(image)) || uint64(len(image))-offset < uint64(len(instruction)) {
		return false
	}
	copy(instruction[:], image[offset:offset+uint64(len(instruction))])
	cubinCodeCache.order.MoveToFront(e)
	return true
}
