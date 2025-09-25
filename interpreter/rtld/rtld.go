// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rtld // import "go.opentelemetry.io/ebpf-profiler/interpreter/rtld"

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// data holds the Uprobe link to keep it in memory
type data struct {
	path string
	link link.Link
}

// instance represents a per-PID instance of the rtld interpreter
type instance struct {
	interpreter.InstanceStubs
}

// Loader detects if the ELF file contains the rtld:map_complete USDT probe
func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	// Check if this is ld.so by examining the filename
	fileName := info.FileName()
	if !strings.Contains(fileName, "ld-") && !strings.Contains(fileName, "ld.so") {
		return nil, nil
	}

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// Look for .note.stapsdt section which contains USDT probes
	sec := ef.Section(".note.stapsdt")
	if sec == nil {
		log.Debugf("No .note.stapsdt section found in %s", fileName)
		return nil, nil
	}

	// Parse USDT probes from the section
	probes, err := pfelf.ParseUSDTProbes(sec)
	if err != nil {
		return nil, fmt.Errorf("failed to parse USDT probes: %w", err)
	}
	prog := "usdt_rtld_map_complete"
	// Look for rtld:map_complete probe
	for _, probe := range probes {
		if probe.Provider != "rtld" || probe.Name != "map_complete" {
			continue
		}
		log.Debugf("Found rtld:map_complete USDT probe in %s at 0x%x",
			fileName, probe.Location)
		link, err := ebpf.AttachUSDTProbes(0, fileName, prog, []pfelf.USDTProbe{probe}, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to attach uprobe to rtld:map_complete usdt: %w", err)
		}
		return &data{
			path: fileName,
			link: link,
		}, nil
	}

	return nil, nil
}

// Attach attaches the uprobe to the rtld:map_complete USDT probe
func (d *data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address,
	_ remotememory.RemoteMemory) (interpreter.Instance, error) {
	return &instance{}, nil
}

// Detach removes the uprobe
func (i *instance) Detach(_ interpreter.EbpfHandler, pid libpf.PID) error {
	log.Debugf("[rtld] Detach called for PID %d", pid)
	return nil
}

// Unload cleans up the uprobe link
func (d *data) Unload(_ interpreter.EbpfHandler) {
	if d.link != nil {
		if err := d.link.Close(); err != nil {
			log.Errorf("[rtld] Failed to close uprobe link: %v", err)
		}
		d.link = nil
	}
	log.Debugf("[rtld] Unloaded uprobe for %s", d.path)
}
