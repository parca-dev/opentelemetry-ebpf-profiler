// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"container/list"
	"sync"
)

// DefaultCubinCodeCacheSize disables memory-only mnemonic caching by default.
// File-backed sources, identity metadata and queued uploads are unaffected.
const DefaultCubinCodeCacheSize uint64 = 0

type cubinCodeEntry struct {
	crc   uint64
	image []byte
}

// Instruction reads copy just 16 bytes while holding the lock. Neither metadata
// nor readers can pin an evicted image in memory after the lock is released.
var cubinCodeCache = struct {
	sync.Mutex
	limit   uint64
	used    uint64
	entries map[uint64]*list.Element
	order   list.List // Most recently sampled at the front.
}{
	limit:   DefaultCubinCodeCacheSize,
	entries: make(map[uint64]*list.Element),
}

// SetCubinCodeCacheSize changes the byte budget, evicting old images if needed.
// Zero disables in-memory mnemonic enrichment, not samples or debug-file uploads.
func SetCubinCodeCacheSize(size uint64) {
	cubinCodeCache.Lock()
	defer cubinCodeCache.Unlock()
	cubinCodeCache.limit = size
	for cubinCodeCache.used > size {
		removeCubinCode(cubinCodeCache.order.Back())
	}
}

// removeCubinCode requires cubinCodeCache's lock.
func removeCubinCode(e *list.Element) {
	entry := e.Value.(cubinCodeEntry)
	cubinCodeCache.used -= uint64(cap(entry.image))
	delete(cubinCodeCache.entries, entry.crc)
	cubinCodeCache.order.Remove(e)
}

// CacheCubinCode retains an immutable image for memory-only instruction lookup.
// The caller must not modify image afterwards. An image larger than the budget
// is skipped without evicting other cubins. Repeated metadata notifications do
// not refresh recency; only instruction reads do. File-backed cubins need no copy.
func CacheCubinCode(info *CubinInfo, image []byte) {
	cubinCodeCache.Lock()
	defer cubinCodeCache.Unlock()
	if info.Source != nil {
		if e, ok := cubinCodeCache.entries[info.CRC]; ok {
			removeCubinCode(e)
		}
		return
	}
	if _, ok := cubinCodeCache.entries[info.CRC]; ok {
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
	e := cubinCodeCache.order.PushFront(cubinCodeEntry{crc: info.CRC, image: image})
	cubinCodeCache.entries[info.CRC] = e
	cubinCodeCache.used += size
}

func hasCubinCode(crc uint64) bool {
	cubinCodeCache.Lock()
	defer cubinCodeCache.Unlock()
	_, ok := cubinCodeCache.entries[crc]
	return ok
}

func readCubinInstruction(crc, offset uint64, instruction *[16]byte) bool {
	cubinCodeCache.Lock()
	defer cubinCodeCache.Unlock()
	e, ok := cubinCodeCache.entries[crc]
	if !ok {
		return false
	}
	image := e.Value.(cubinCodeEntry).image
	if offset > uint64(len(image)) || uint64(len(image))-offset < uint64(len(instruction)) {
		return false
	}
	copy(instruction[:], image[offset:offset+uint64(len(instruction))])
	cubinCodeCache.order.MoveToFront(e)
	return true
}
