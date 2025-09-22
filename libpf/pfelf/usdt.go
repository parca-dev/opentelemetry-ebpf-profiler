// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf"

import (
	"encoding/binary"
	"strings"
)

// USDTProbe represents a USDT probe found in ELF
type USDTProbe struct {
	Provider        string
	Name            string
	Location        uint64
	Base            uint64
	SemaphoreOffset uint64
	Arguments       string
}

// ParseUSDTProbes reads USDT probe information from ELF .note.stapsdt section
func ParseUSDTProbes(section *Section) ([]USDTProbe, error) {
	var probes []USDTProbe

	// Find .note.stapsdt section
	data, err := section.Data(16 * 1024)
	if err != nil {
		return nil, err
	}

	// Parse note entries
	offset := 0
	for offset < len(data) {
		if offset+12 > len(data) {
			break
		}

		// Note header: namesz(4) + descsz(4) + type(4)
		namesz := binary.LittleEndian.Uint32(data[offset : offset+4])
		descsz := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		noteType := binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		offset += 12

		if noteType != 3 { // NT_STAPSDT
			// Skip this note
			nameEnd := offset + int((namesz+3)&^3) // align to 4 bytes
			descEnd := nameEnd + int((descsz+3)&^3)
			offset = descEnd
			continue
		}

		// Skip owner name (should be "stapsdt")
		nameEnd := offset + int((namesz+3)&^3)

		if nameEnd+int(descsz) > len(data) {
			break
		}

		// Parse descriptor
		desc := data[nameEnd : nameEnd+int(descsz)]
		if len(desc) < 24 { // 3 uint64 values
			offset = nameEnd + int((descsz+3)&^3)
			continue
		}

		location := binary.LittleEndian.Uint64(desc[0:8])
		base := binary.LittleEndian.Uint64(desc[8:16])
		semaphore := binary.LittleEndian.Uint64(desc[16:24])

		// Parse strings: provider\0probe\0arguments\0
		stringData := desc[24:]
		strings := strings.Split(string(stringData), "\x00")
		if len(strings) >= 3 {
			probe := USDTProbe{
				Provider:        strings[0],
				Name:            strings[1],
				Location:        location,
				Base:            base,
				SemaphoreOffset: semaphore,
				Arguments:       strings[2],
			}
			probes = append(probes, probe)
		}

		offset = nameEnd + int((descsz+3)&^3)
	}

	return probes, nil
}
