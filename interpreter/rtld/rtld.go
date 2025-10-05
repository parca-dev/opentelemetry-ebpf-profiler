// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rtld // import "go.opentelemetry.io/ebpf-profiler/interpreter/rtld"

import (
	"fmt"
	"path"
	"regexp"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// LdsoRegexp matches ld.so filenames across different distributions
var LdsoRegexp = regexp.MustCompile(
	`^ld(?:-linux)?(?:-x86-64|-aarch64)?\.so\.\d+$|` +
		`^ld\.so\.\d+$|` +
		`^ld-\d+\.\d+\.so$|` +
		`^ld-musl-[^/]+\.so\.\d+$`)

// data holds the Uprobe link to keep it in memory
type data struct {
	path      string
	usePoller bool
	probe     pfelf.USDTProbe
	lc        interpreter.LinkCloser
}

// instance represents a per-PID instance of the rtld interpreter
type instance struct {
	interpreter.InstanceStubs
	usePoller bool
	lc        interpreter.LinkCloser
}

// Loader detects if the ELF file contains the rtld:map_complete USDT probe
func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	// Check if this is ld.so by examining just the basename
	fileName := info.FileName()
	baseName := path.Base(fileName)
	if !LdsoRegexp.MatchString(baseName) {
		return nil, nil
	}

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// Look for .note.stapsdt section which contains USDT probes
	sec := ef.Section(".note.stapsdt")
	if sec == nil {
		log.Debugf("No .note.stapsdt section found in %s, will use poller fallback", fileName)
		return &data{
			path:      fileName,
			usePoller: true,
		}, nil
	}

	// Parse USDT probes from the section
	probes, err := pfelf.ParseUSDTProbes(sec)
	if err != nil {
		return nil, fmt.Errorf("failed to parse USDT probes: %w", err)
	}
	// Look for rtld:map_complete probe
	for _, probe := range probes {
		if probe.Provider != "rtld" || probe.Name != "map_complete" {
			continue
		}
		log.Debugf("Found rtld:map_complete USDT probe in %s at 0x%x",
			fileName, probe.Location)

		return &data{
			probe: probe,
			path:  fileName,
		}, nil
	}

	// No rtld:map_complete probe found, use poller fallback
	log.Debugf("No rtld:map_complete probe found in %s, will use poller fallback", fileName)
	return &data{
		path:      fileName,
		usePoller: true,
	}, nil
}

// Attach attaches the uprobe to the rtld:map_complete USDT probe or registers with poller
func (d *data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address,
	_ remotememory.RemoteMemory) (interpreter.Instance, error) {
	if d.usePoller {
		// Register this PID with the global poller
		// Create a trigger function that calls TriggerProcessSync on the ebpf handler
		triggerFunc := func(triggerPID libpf.PID) {
			if err := ebpf.TriggerProcessSync(triggerPID); err != nil {
				log.Debugf("[rtld] TriggerProcessSync failed for PID %d: %v", triggerPID, err)
			}
		}
		getPoller(triggerFunc).registerPID(pid)
		log.Debugf("[rtld] Registered PID %d with poller for %s", pid, d.path)

		return &instance{usePoller: true}, nil
	} else {
		prog := "usdt_rtld_map_complete"
		lc, err := ebpf.AttachUSDTProbes(
			pid, d.path, prog, []pfelf.USDTProbe{d.probe}, nil, nil, false)
		if err != nil {
			return nil, fmt.Errorf("failed to attach uprobe to rtld:map_complete usdt: %w", err)
		}
		log.Debugf("[rtld] Using USDT probe for PID %d on %s", pid, d.path)
		d.lc = lc
		return &instance{lc: lc}, nil
	}
}

// Detach removes the uprobe or deregisters from poller
func (i *instance) Detach(_ interpreter.EbpfHandler, pid libpf.PID) error {
	log.Debugf("[rtld] Detach called for PID %d", pid)
	if i.usePoller {
		// Deregister this PID from the global poller
		// Pass a nil trigger function since we're just deregistering
		getPoller(nil).deregisterPID(pid)
		log.Debugf("[rtld] Deregistered PID %d from poller", pid)
	}
	return nil
}

// Unload cleans up the uprobe link
func (d *data) Unload(_ interpreter.EbpfHandler) {
	if d.lc != nil {
		if err := d.lc.Unload(); err != nil {
			log.Errorf("[rtld] Failed to unload uprobe link: %v", err)
		}
		d.lc = nil
	}
	log.Debugf("[rtld] Unloaded uprobe for %s", d.path)
}
