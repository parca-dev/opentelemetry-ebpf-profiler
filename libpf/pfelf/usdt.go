// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf"

import (
	"debug/elf"

	"github.com/parca-dev/usdt"
)

// USDTProbe is an alias for usdt.Probe for backwards compatibility.
type USDTProbe = usdt.Probe

// pfelfELFReader adapts pfelf.File to the usdt.ELFReader interface.
type pfelfELFReader struct {
	f *File
}

func (r *pfelfELFReader) Sections() ([]usdt.ELFSection, error) {
	if err := r.f.LoadSections(); err != nil {
		return nil, err
	}
	sections := make([]usdt.ELFSection, len(r.f.Sections))
	for i, s := range r.f.Sections {
		sections[i] = usdt.ELFSection{
			Name: s.Name,
			Addr: s.Addr,
		}
		// Only read data for sections the parser needs
		if s.Name == ".note.stapsdt" || s.Name == ".stapsdt.base" {
			data, err := s.Data(16 * 1024)
			if err != nil {
				return nil, err
			}
			sections[i].Data = data
		}
	}
	return sections, nil
}

func (r *pfelfELFReader) LoadSegments() []usdt.ELFProg {
	var segs []usdt.ELFProg
	for _, p := range r.f.Progs {
		if elf.ProgType(p.Type) == elf.PT_LOAD {
			segs = append(segs, usdt.ELFProg{
				Vaddr: p.Vaddr,
				Memsz: p.Memsz,
				Off:   p.Off,
			})
		}
	}
	return segs
}

// ParseUSDTProbes reads USDT probe information from ELF .note.stapsdt section.
// It delegates to the usdt package via the pfelf adapter.
func (f *File) ParseUSDTProbes() ([]usdt.Probe, error) {
	return usdt.ParseProbes(&pfelfELFReader{f: f})
}
