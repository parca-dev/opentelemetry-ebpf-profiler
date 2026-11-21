// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func deviceInfoEvent(pid, dev uint32, uuid [16]byte, pci string) *CuptiDeviceInfoEvent {
	ev := &CuptiDeviceInfoEvent{EventType: EventTypeDeviceInfo, Pid: pid, DeviceID: dev,
		UUID: uuid}
	copy(ev.PCIBusID[:], pci)
	return ev
}

// Layout of struct device_info_event in cuda.ebpf.c.
func TestDeviceInfoEventLayout(t *testing.T) {
	var ev CuptiDeviceInfoEvent
	assert.Equal(t, uintptr(64), unsafe.Sizeof(ev))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(ev.UUID))
	assert.Equal(t, uintptr(32), unsafe.Offsetof(ev.PCIBusID))
	assert.Equal(t, uintptr(16), unsafe.Sizeof(CuptiCubinUnloadedEvent{}))
}

func TestDeviceInfoPerProcessOrdinal(t *testing.T) {
	const pidA, pidB = 9101, 9102
	t.Cleanup(func() { DeleteDeviceInfos(pidA); DeleteDeviceInfos(pidB) })
	gpu0 := [16]byte{0x9a, 0x7e, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60,
		0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8}
	gpu1 := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	// pidB runs with CUDA_VISIBLE_DEVICES=1,0: its ordinal 0 is pidA's 1.
	HandleDeviceInfoEvent(deviceInfoEvent(pidA, 0, gpu0, "0000:01:00.0"))
	HandleDeviceInfoEvent(deviceInfoEvent(pidA, 1, gpu1, "0000:02:00.0"))
	HandleDeviceInfoEvent(deviceInfoEvent(pidB, 0, gpu1, "0000:02:00.0"))

	a1, ok := LoadDeviceInfo(pidA, 1)
	require.True(t, ok)
	b0, ok := LoadDeviceInfo(pidB, 0)
	require.True(t, ok)
	assert.Equal(t, a1.UUID, b0.UUID)
	assert.Equal(t, "0000:02:00.0", b0.PCIBusID)
	assert.Equal(t, uint32(0), b0.DeviceID)
	_, ok = LoadDeviceInfo(pidB, 1)
	assert.False(t, ok)

	a0, ok := LoadDeviceInfo(pidA, 0)
	require.True(t, ok)
	assert.Equal(t, "GPU-9a7e1b2c-3d4e-5f60-7182-93a4b5c6d7e8", a0.UUIDString())

	// Replays are idempotent.
	HandleDeviceInfoEvent(deviceInfoEvent(pidA, 0, gpu0, "0000:01:00.0"))
	again, _ := LoadDeviceInfo(pidA, 0)
	assert.Equal(t, a0, again)

	DeleteDeviceInfos(pidA)
	_, ok = LoadDeviceInfo(pidA, 0)
	assert.False(t, ok)
	_, ok = LoadDeviceInfo(pidB, 0)
	assert.True(t, ok)
}

func TestPCSampleDeviceInfo(t *testing.T) {
	const pid = 9103
	t.Cleanup(func() { DeleteDeviceInfos(pid) })
	uuid := [16]byte{0xaa, 15: 0xbb}
	HandleDeviceInfoEvent(deviceInfoEvent(pid, 2, uuid, ""))

	info, ok := PCSampleDeviceInfo(pcMeta(pid, &PCSampleOrigin{DeviceID: 2, HasDevice: true}))
	require.True(t, ok)
	assert.Equal(t, uuid, info.UUID)
	assert.Empty(t, info.PCIBusID)

	// Samples from a parcagpu without the device argument have no ordinal.
	_, ok = PCSampleDeviceInfo(pcMeta(pid, &PCSampleOrigin{DeviceID: 2}))
	assert.False(t, ok)
	_, ok = PCSampleDeviceInfo(pcMeta(pid, nil))
	assert.False(t, ok)
	_, ok = PCSampleDeviceInfo(pcMeta(pid, &PCSampleOrigin{DeviceID: 3, HasDevice: true}))
	assert.False(t, ok)
}
