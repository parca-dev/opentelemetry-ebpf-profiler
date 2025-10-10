// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package util // import "go.opentelemetry.io/ebpf-profiler/util"

import (
	"bytes"
	"fmt"
	"math/bits"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf/hash"
	"golang.org/x/sys/unix"
)

// IsValidString checks if string is UTF-8-encoded and only contains expected characters.
func IsValidString(s string) bool {
	if s == "" {
		return false
	}
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// NextPowerOfTwo returns input value if it's a power of two,
// otherwise it returns the next power of two.
func NextPowerOfTwo(v uint32) uint32 {
	if v == 0 {
		return 1
	}
	return 1 << bits.Len32(v-1)
}

// AtomicUpdateMaxUint32 updates the value in store using atomic memory primitives. newValue will
// only be placed in store if newValue is larger than the current value in store.
// To avoid inconsistency parallel updates to store should be avoided.
func AtomicUpdateMaxUint32(store *atomic.Uint32, newValue uint32) {
	for {
		// Load the current value
		oldValue := store.Load()
		if newValue <= oldValue {
			// No update needed.
			break
		}
		if store.CompareAndSwap(oldValue, newValue) {
			// The value was atomically updated.
			break
		}
		// The value changed between load and update attempt.
		// Retry with the new value.
	}
}

// VersionUint returns a single integer composed of major, minor, patch.
func VersionUint(major, minor, patch uint32) uint32 {
	return (major << 16) + (minor << 8) + patch
}

// Range describes a range with Start and End values.
type Range struct {
	Start uint64
	End   uint64
}

// OnDiskFileIdentifier can be used as unique identifier for a file.
// It is a structure to identify a particular file on disk by
// deviceID and inode number.
type OnDiskFileIdentifier struct {
	DeviceID uint64 // dev_t as reported by stat.
	InodeNum uint64 // ino_t should fit into 64 bits
}

func (odfi OnDiskFileIdentifier) Hash32() uint32 {
	return uint32(hash.Uint64(odfi.InodeNum) + odfi.DeviceID)
}

// GetCurrentKernelVersion returns the major, minor and patch version of the kernel of the host
// from the utsname struct.
func GetCurrentKernelVersion() (major, minor, patch uint32, err error) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return 0, 0, 0, fmt.Errorf("could not get Kernel Version: %v", err)
	}
	_, _ = fmt.Fscanf(bytes.NewReader(uname.Release[:]), "%d.%d.%d", &major, &minor, &patch)
	return major, minor, patch, nil
}

var (
	// testOnlyMultiUprobeOverride allows tests to override HasMultiUprobeSupport
	testOnlyMultiUprobeOverride *bool
	// multiUprobeSupportCache caches the result of probing for multi-uprobe support
	multiUprobeSupportOnce   sync.Once
	multiUprobeSupportCached bool
)

// SetTestOnlyMultiUprobeSupport overrides HasMultiUprobeSupport for testing.
// Pass nil to restore normal behavior.
func SetTestOnlyMultiUprobeSupport(override *bool) {
	testOnlyMultiUprobeOverride = override
}

// probeBpfGetAttachCookie tests if the kernel supports bpf_get_attach_cookie by attempting
// to load a minimal BPF program that uses it. This is more reliable than checking kernel
// versions since support can be backported.
func probeBpfGetAttachCookie() bool {
	// Create a minimal program that calls bpf_get_attach_cookie
	// This is equivalent to libbpf's probe_kern_bpf_cookie function
	insns := asm.Instructions{
		// Call bpf_get_attach_cookie() - BPF_FUNC_get_attach_cookie = 80
		asm.FnGetAttachCookie.Call(),
		// Exit
		asm.Return(),
	}

	spec := &ebpf.ProgramSpec{
		Type:         ebpf.TracePoint,
		Instructions: insns,
		License:      "GPL",
	}

	prog, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogDisabled: true,
	})
	if err != nil {
		return false
	}
	if err := prog.Close(); err != nil {
		log.Warnf("Failed to close test program: %v", err)
	}
	return true
}

// HasMultiUprobeSupport checks if the kernel supports uprobe multi-attach.
// Multi-uprobes are needed because single-shot uprobes don't work for shared libraries.
// This function probes for bpf_get_attach_cookie support, which is required for
// multi-uprobes and was introduced alongside them in kernel 6.6.
//
// Note: This function requires CAP_BPF or CAP_SYS_ADMIN capabilities to load the probe
// program. The profiler should already have these privileges.
func HasMultiUprobeSupport() bool {
	if testOnlyMultiUprobeOverride != nil {
		return *testOnlyMultiUprobeOverride
	}

	multiUprobeSupportOnce.Do(func() {
		multiUprobeSupportCached = probeBpfGetAttachCookie()
	})

	return multiUprobeSupportCached
}

// ProgArrayReferences returns a list of instructions which load a specified tail
// call FD.
func ProgArrayReferences(perfTailCallMapFD int, insns asm.Instructions) []int {
	insNos := []int{}
	for i := range insns {
		ins := &insns[i]
		if asm.OpCode(ins.OpCode.Class()) != asm.OpCode(asm.LdClass) {
			continue
		}
		m := ins.Map()
		if m == nil {
			continue
		}
		if perfTailCallMapFD == m.FD() {
			insNos = append(insNos, i)
		}
	}
	return insNos
}

// Convert a C-string to Go string.
func GoString(cstr []byte) string {
	index := bytes.IndexByte(cstr, byte(0))
	if index < 0 {
		index = len(cstr)
	}
	return strings.Clone(unsafe.String(unsafe.SliceData(cstr), index))
}
