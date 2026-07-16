// Copyright 2024 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// Records all the "global" pointers we've seen.
type vmMap map[libpf.Address]struct{}

// Records all the JIT regions we've seen, value is SynchronizeMappings
// generation.
type regionMap map[process.RawMapping]int

type regionKey struct {
	start, end uint64
}

type luajitData struct {
	// The distance from the "g" pointer in the GG_State struct to the start of the dispatch table.
	g2Dispatch uint16
	// The distance from the "g" pointer in the GG_State struct to the start of the trace array
	// in the jit_State struct.
	g2Traces uint16
	// Offset of cur_L field in the global_State struct.
	currentLOffset uint16
	// Offset of jit_base within global_State (relative to G). Extracted separately
	// because it is not always adjacent to cur_L (tarantool inserts mem_L between).
	g2jitbase uint16
	// Used only while loading to reject Tarantool's known-wrong fallback.
	jitBaseExtracted bool
	// How to step over the interpreter C frame on the native handback, taken from
	// the interpreter region's stack delta. cframeSizeInterp is the CFA offset;
	// interpFP is 1 when frame-pointer based. Zero means use the default.
	cframeSizeInterp uint16
	interpFP         uint16
	// Size to step over a JIT trace's C frame on the native handback. On x86 this
	// is the extracted interpreter cframe plus the interp-to-trace transition.
	cframeSizeJIT uint16
	// Offset of the previous-C-frame link. Tarantool's x64 VM frame has two
	// additional words before this link compared with OpenResty/standard LuaJIT.
	cframePrevOffset uint16
}

type luajitInstance struct {
	rm         remotememory.RemoteMemory
	protos     map[libpf.Address]*proto
	jitRegions regionMap
	pid        libpf.PID
	ebpf       interpreter.EbpfHandler
	// Map of g's we've seen, populated by the symbolizer goroutine and
	// consumed in SynchronizeMappings so needs to be protected by a mutex.
	mu  sync.Mutex
	vms vmMap

	// Currently mapped prefixes for each vms traces
	prefixesByG map[libpf.Address][]lpm.Prefix

	// Currently mapped prefixes for entire memory regions
	prefixes map[regionKey][]lpm.Prefix

	// Hash of the traces for each vm
	traceHashes map[libpf.Address]uint64
	cycle       int

	g2Traces      uint16
	cframeSizeJIT uint16
}

var (
	_ interpreter.Data     = &luajitData{}
	_ interpreter.Instance = &luajitInstance{}
)

func (d *luajitData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address,
	rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	cdata := support.LuaJITProcInfo{
		G2dispatch:         d.g2Dispatch,
		Cur_L_offset:       d.currentLOffset,
		Cframe_size_jit:    d.cframeSizeJIT,
		G2jitbase:          d.g2jitbase,
		Cframe_size_interp: d.cframeSizeInterp,
		Interp_fp:          d.interpFP,
		Cframe_prev_offset: d.cframePrevOffset,
	}
	if err := ebpf.UpdateProcData(libpf.LuaJIT, pid, unsafe.Pointer(&cdata)); err != nil {
		return nil, err
	}

	return &luajitInstance{rm: rm,
		pid:           pid,
		ebpf:          ebpf,
		protos:        make(map[libpf.Address]*proto),
		jitRegions:    make(regionMap),
		prefixes:      make(map[regionKey][]lpm.Prefix),
		prefixesByG:   make(map[libpf.Address][]lpm.Prefix),
		vms:           make(vmMap),
		traceHashes:   make(map[libpf.Address]uint64),
		g2Traces:      d.g2Traces,
		cframeSizeJIT: d.cframeSizeJIT,
	}, nil
}

func (d *luajitData) Unload(_ interpreter.EbpfHandler) {}

func (l *luajitInstance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	// Clear memory ranges
	for _, prefixes := range l.prefixes {
		for _, prefix := range prefixes {
			_ = ebpf.DeletePidInterpreterMapping(pid, prefix)
		}
	}
	// Clear trace ranges
	for _, prefixes := range l.prefixesByG {
		for _, prefix := range prefixes {
			_ = ebpf.DeletePidInterpreterMapping(pid, prefix)
		}
	}
	return ebpf.DeleteProcData(libpf.LuaJIT, pid)
}

func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	base := path.Base(info.FileName())
	// Tarantool statically links LuaJIT into its main executable, so there is
	// no separate libluajit-5.1.so mapping to match on.
	if !strings.HasPrefix(base, "libluajit-5.1.so") &&
		!strings.HasPrefix(base, "luajit") &&
		base != "nginx" && base != "openresty" && base != "tarantool" {
		return nil, nil
	}

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// When the binary is unstripped (e.g. tarantool), lj_vm_asm_begin marks the
	// exact start of the VM interpreter. Anchor the interpreter-range detection
	// to it: the stack-delta heuristic alone can match an unrelated large gap
	// (observed on x86 tarantool — it matched 0x164469 instead of the real
	// lj_vm_asm_begin 0x261ca0, then failed the start-address sanity check).
	// lj_vm_asm_begin is a hidden .symtab symbol; raw ef.LookupSymbol only finds
	// dynamic symbols, so use scanSymbols (which reads .symtab via VisitSymbols),
	// matching how extractOffsets resolves it.
	foundSymbols := scanSymbols(ef)
	var asmBegin uint64
	if sym, ok := foundSymbols[libpf.SymbolName("lj_vm_asm_begin")]; ok {
		asmBegin = uint64(sym.Address)
	}

	luaInterp, err := extractInterpreterBounds(info.Deltas(), cframeSize, asmBegin)
	if err != nil {
		return nil, err
	}
	logf("lj: interp range %v", luaInterp)

	ljd := &luajitData{
		cframePrevOffset: cframePrevOffsetForExecutable(base),
	}
	// Derive the interpreter C-frame unwind from the VM region's own stack
	// delta. The hardcoded LuaJIT constants do not match every embedding.
	if param, fp, ok := interpCframeUnwind(info.Deltas(), luaInterp.Start); ok {
		ljd.cframeSizeInterp = param
		ljd.interpFP = fp
		logf("lj: interp cframe size %d fp %d", param, fp)
	}
	// A JIT trace uses the VM gate's C frame plus a 16-byte transition frame.
	// On SP-based x86 builds, derive that from the extracted interpreter frame;
	// frame-pointer-based arm64 retains the architecture constant.
	ljd.cframeSizeJIT = deriveJITCframeSize(ljd.cframeSizeInterp, ljd.interpFP)
	logf("lj: cframe size jit %d", ljd.cframeSizeJIT)

	if err = extractOffsets(ef, ljd, luaInterp, foundSymbols); err != nil {
		return nil, err
	}
	// Tarantool's global_State contains mem_L, so the OpenResty cur_L+8
	// fallback is known to be wrong. Fail attachment rather than silently
	// emitting corrupt JIT stacks if the hidden exit-handler symbol disappears.
	if base == "tarantool" && !ljd.jitBaseExtracted {
		return nil, errors.New("failed to extract jit_base offset required for Tarantool")
	}

	logf("lj: offsets %+v", ljd)

	if err = ebpf.UpdateInterpreterOffsets(support.ProgUnwindLuaJIT, info.FileID(),
		[]util.Range{luaInterp}); err != nil {
		return nil, err
	}

	return ljd, nil
}

func cframePrevOffsetForExecutable(base string) uint16 {
	// Match Loader's exact executable-name contract. A renamed binary is not
	// recognized as Tarantool by the loader and must not receive its layout.
	if base == "tarantool" {
		return tarantoolCframePrevOffset
	}
	return defaultCframePrevOffset
}

// LuaJIT's interpreter isn't a function, its a raw chunk of assembly code with direct threaded
// jumps at end of each opcode. The public entrypoints (lua_pcall/lua_resume) call the lj_vm_pcall
// function at the end of this blob which set up the interpreter and starts executing.
// Even though its not a normal function an eh_frame entry is created for it, its really
// big and has a somewhat unique FDE we can pick out. We could tighten this up by looking for
// direct jumps to the start of the interpreter (one can be found lj_dispatch_update) but we'd
// still need to consult the stack deltas to get the end of the interpreter.
func extractInterpreterBounds(deltas sdtypes.StackDeltaArray, param int32,
	asmBegin uint64) (util.Range, error) {
	// If lj_vm_asm_begin is known (unstripped binary), the interpreter range
	// starts exactly at that symbol. Return the delta gap that starts there
	// rather than the first large gap matching the unwind pattern, which can be
	// an unrelated function on some builds (x86 tarantool).
	if asmBegin != 0 {
		// The VM asm is one large delta interval, but its start can sit a few
		// bytes below lj_vm_asm_begin (the preceding function's unwind info
		// extends to just before the symbol). Match the interval that CONTAINS
		// the symbol and is large (the interpreter), then start the range exactly
		// at the symbol so it matches the lj_vm_asm_begin sanity check.
		for i := 0; i < len(deltas)-1; i++ {
			if deltas[i].Address <= asmBegin && asmBegin < deltas[i+1].Address &&
				deltas[i+1].Address-asmBegin > 10_000 {
				return util.Range{Start: asmBegin, End: deltas[i+1].Address}, nil
			}
		}
		// Fall through to the heuristic if the symbol isn't in a large interval.
	}
	for i := 0; i < len(deltas)-1; i++ {
		d, next := &deltas[i], &deltas[i+1]
		if next.Address-d.Address > 10_000 {
			// The first case covers x86 w/ dwarf and old versions of luajit ARM that used dwarf and
			// the second covers more recent arm versions that use frame pointers.
			if d.Info.BaseReg == support.UnwindRegSp && d.Info.Param == param ||
				d.Info.BaseReg == support.UnwindRegFp && d.Info.Param == 16 {
				return util.Range{Start: d.Address, End: next.Address}, nil
			}
		}
	}

	return util.Range{}, errors.New("failed to find interpreter range")
}

// deriveJITCframeSize adds LuaJIT's transition frame to SP-based interpreter
// frames. FP-based or unavailable unwind data retains the architecture default.
func deriveJITCframeSize(interpSize, interpFP uint16) uint16 {
	if interpSize != 0 && interpFP == 0 &&
		interpSize <= uint16(0xffff-cframeJITTransitionSize) {
		return interpSize + cframeJITTransitionSize
	}
	return uint16(cframeSizeJIT)
}

// interpCframeUnwind returns how to step over the interpreter's C frame when
// handing back to the native unwinder. It uses the stack delta covering the VM
// assembly: param is the CFA offset and fp is one for frame-pointer-based CFA.
func interpCframeUnwind(deltas sdtypes.StackDeltaArray, interpStart uint64) (param, fp uint16, ok bool) {
	for i := 0; i < len(deltas)-1; i++ {
		if deltas[i].Address <= interpStart && interpStart < deltas[i+1].Address {
			p := deltas[i].Info.Param
			if p <= 0 || p > 0xffff {
				return 0, 0, false
			}
			switch deltas[i].Info.BaseReg {
			case support.UnwindRegFp:
				return uint16(p), 1, true
			case support.UnwindRegSp:
				return uint16(p), 0, true
			default:
				return 0, 0, false
			}
		}
	}
	return 0, 0, false
}

func (l *luajitInstance) getVMList() []libpf.Address {
	l.mu.Lock()
	defer l.mu.Unlock()
	gs := make([]libpf.Address, 0, len(l.vms))
	for g := range l.vms {
		gs = append(gs, g)
	}
	return gs
}

func (l *luajitInstance) addJITRegion(ebpf interpreter.EbpfHandler, pid libpf.PID,
	start, end uint64) error {
	prefixes, err := lpm.CalculatePrefixList(start, end)
	if err != nil {
		logf("lj: failed to calculate lpm: %v", err)
		return err
	}
	logf("lj: add JIT region pid(%v) %#x:%#x", pid, start, end)
	for _, prefix := range prefixes {
		// TODO: fix these: WARN[0267] Failed to lookup file ID 0x2a00000000
		fileID := support.LJFileId << 32
		if err := ebpf.UpdatePidInterpreterMapping(pid, prefix, support.ProgUnwindLuaJIT,
			host.FileID(fileID), 0); err != nil {
			return err
		}
	}
	k := regionKey{start: start, end: end}
	l.prefixes[k] = prefixes
	return nil
}

func (l *luajitInstance) addTrace(ebpf interpreter.EbpfHandler, pid libpf.PID, t trace, g,
	spadjust uint64) ([]lpm.Prefix, error) {
	start, end := t.mcode, t.mcode+uint64(t.szmcode)
	prefixes, err := lpm.CalculatePrefixList(start, end)
	if err != nil {
		logf("lj: failed to calculate lpm: %v", err)
		return nil, err
	}
	logf("lj: add trace mapping for pid(%v) %x:%x", pid, start, end)
	for _, prefix := range prefixes {
		fileID := support.LJFileId<<32 | spadjust
		if err := ebpf.UpdatePidInterpreterMapping(pid, prefix, support.ProgUnwindLuaJIT,
			host.FileID(fileID), g); err != nil {
			return nil, err
		}
	}
	return prefixes, nil
}

func (l *luajitInstance) SynchronizeMappings(ebpf interpreter.EbpfHandler,
	_ reporter.ExecutableReporter, pr process.Process, mappings []process.RawMapping) error {
	return l.synchronizeMappings(ebpf, pr.PID(), mappings)
}

func (l *luajitInstance) synchronizeMappings(ebpf interpreter.EbpfHandler, pid libpf.PID,
	mappings []process.RawMapping) error {
	cycle := l.cycle
	l.cycle++
	for i := range mappings {
		m := &mappings[i]
		if !m.IsAnonymous() || !m.IsExecutable() {
			continue
		}
		l.jitRegions[*m] = cycle
	}

	// Remove old ones
	for m, c := range l.jitRegions {
		k := regionKey{start: m.Vaddr, end: m.Vaddr + m.Length}
		if c != cycle {
			for _, prefix := range l.prefixes[k] {
				if err := ebpf.DeletePidInterpreterMapping(pid, prefix); err != nil {
					return errors.Join(err, fmt.Errorf("failed to delete prefix %v", prefix))
				}
			}
			delete(l.jitRegions, m)
			delete(l.prefixes, k)
		}
	}

	// Add new ones
	for m := range l.jitRegions {
		k := regionKey{start: m.Vaddr, end: m.Vaddr + m.Length}
		if _, ok := l.prefixes[k]; !ok {
			if err := l.addJITRegion(ebpf, pid, m.Vaddr, m.Vaddr+m.Length); err != nil {
				return errors.Join(err, fmt.Errorf("failed to add JIT region %v", m))
			}
		}
	}

	return l.processVMs(ebpf, pid)
}

func (l *luajitInstance) processVMs(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	var badVMs []libpf.Address
	for _, g := range l.getVMList() {
		hash, traces, err := loadTraces(g+libpf.Address(l.g2Traces), l.rm)
		if err != nil {
			// if g is bad remove it
			log.Warnf("LuaJIT instance (%v) deleted: %v", g, err)
			badVMs = append(badVMs, g)
			continue
		}
		// Don't do anything if nothing changed.
		if hash == l.traceHashes[g] {
			continue
		}

		// We don't bother trying to keep things in sync, just delete them all and re-add them.
		prefixes := l.prefixesByG[g]
		l.prefixesByG[g] = nil
		for _, prefix := range prefixes {
			_ = ebpf.DeletePidInterpreterMapping(pid, prefix)
		}

		newPrefixes := []lpm.Prefix{}
	traceLoop:
		for i := range traces {
			t := traces[i]
			// Validate the trace
			foundRegion := false
			for reg := range l.jitRegions {
				if t.mcode >= reg.Vaddr && t.mcode < reg.Vaddr+reg.Length {
					foundRegion = true
					end := t.mcode + uint64(t.szmcode)
					if end > reg.Vaddr+reg.Length {
						log.Errorf("trace %v end goes beyond JIT region, bad szmcode", t)
						continue traceLoop
					}
					break
				}
			}

			if !foundRegion {
				log.Errorf("trace %v not in a JIT region", t)
				continue
			}

			stackDelta := uint64(t.spadjust) + uint64(l.cframeSizeJIT)
			// If this is a side trace, we need to add the spadjust of the root trace but
			// only if they are different.
			//https://github.com/openresty/luajit2/blob/7952882d/src/lj_gdbjit.c#L597
			if t.root != 0 && traces[t.root].spadjust != t.spadjust {
				stackDelta += uint64(traces[t.root].spadjust) + uint64(l.cframeSizeJIT)
			}
			p, err := l.addTrace(ebpf, pid, t, uint64(g), stackDelta)
			if err != nil {
				log.Errorf("Error adding trace(%d): %v", t.traceno, err)
				continue
			}
			newPrefixes = append(newPrefixes, p...)
		}

		log.Infof("LuaJIT traces for pid(%v) added: %d with %d prefixes and removed %d prefixes",
			pid, len(traces), len(newPrefixes), len(prefixes))

		l.prefixesByG[g] = newPrefixes
		l.traceHashes[g] = hash
	}
	l.removeVMs(badVMs)
	return nil
}

func (l *luajitInstance) removeVMs(gs []libpf.Address) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, g := range gs {
		delete(l.vms, g)
	}
}

func (l *luajitInstance) getGCproto(pt libpf.Address) (*proto, error) {
	if pt == 0 {
		return nil, nil
	}
	if gc, ok := l.protos[pt]; ok {
		return gc, nil
	}
	gc, err := newProto(l.rm, pt)
	if err != nil {
		return nil, err
	}
	l.protos[pt] = gc
	return gc, nil
}

// symbolizeFrame symbolizes the previous (up the stack)
func (l *luajitInstance) symbolizeFrame(funcName string, ptAddr libpf.Address,
	pc uint32, frames *libpf.Frames) error {
	pt, err := l.getGCproto(ptAddr)
	if err != nil {
		return err
	}
	line := pt.getLine(pc)
	fileName := pt.getName()
	logf("lj: [%x] %v+%v at %v:%v", ptAddr, funcName, pc, fileName, line)
	frames.Append(&libpf.Frame{
		Type:           libpf.LuaJITFrame,
		FunctionOffset: pc,
		FunctionName:   libpf.Intern(funcName),
		SourceFile:     libpf.Intern(fileName),
		SourceLine:     libpf.SourceLineno(line),
	})
	return nil
}

func (l *luajitInstance) addVM(g libpf.Address) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.vms[g]
	if !ok {
		l.vms[g] = struct{}{}
	}
	return !ok
}

func (l *luajitInstance) Symbolize(frame libpf.EbpfFrame, frames *libpf.Frames, fm libpf.FrameMapping) error {
	if !frame.Type().IsInterpType(libpf.LuaJIT) {
		return interpreter.ErrMismatchInterpreterType
	}

	var funcName string
	ljkind := frame.Data()
	switch ljkind {
	case support.LJNormalFrame:
		if frame.NumVariables() < 3 {
			return errors.New("LuaJIT normal frame not large enough")
		}
		callerPT := libpf.Address(frame.Variable(1))

		pt, err := l.getGCproto(callerPT)
		if err != nil {
			return err
		}

		var0 := frame.Variable(0)
		callerPC := uint32(var0 & 0xFFFFFFFF)
		calleePC := uint32(var0 >> 32)
		funcName = pt.getFunctionName(callerPC)
		calleePT := libpf.Address(frame.Variable(2))
		if err := l.symbolizeFrame(funcName, calleePT,
			calleePC, frames); err != nil {
			return err
		}

		return nil
	case support.LJFFIFunc:
		if frame.NumVariables() < 1 {
			return errors.New("LuaJIT FFI frame not large enough")
		}
		funcId := libpf.Address(frame.Variable(0)) & 7
		switch funcId {
		case 0:
			funcName = "lua-frame"
		case 1:
			funcName = "c-frame"
		case 2:
			funcName = "cont-frame"
		case 3:
			return errors.New("unexpected frame type 3")
		case 4:
			funcName = "lua-pframe"
		case 5:
			funcName = "cpcall"
		case 6:
			funcName = "ff-pcall"
		case 7:
			funcName = "ff-pcall-hook"
		}
		frames.Append(&libpf.Frame{
			Type:         libpf.LuaJITFrame,
			FunctionName: libpf.Intern("LuaJIT FFI: " + funcName),
		})
		return nil
	case support.LJGReport:
		if frame.NumVariables() < 1 {
			return errors.New("LuaJIT G report frame not large enough")
		}
		g := libpf.Address(frame.Variable(0))
		if g != 0 {
			unseen := l.addVM(g)
			if unseen {
				log.Infof("New LuaJIT instance detected: %v", g)
				if l.ebpf.CoredumpTest() {
					return interpreter.ErrLJRestart
				}
			}
		}
		return nil
	default:
		return fmt.Errorf("Unrecognized LuaJIT frame kind: %d", ljkind)
	}

	return nil
}

func (l *luajitInstance) GetAndResetMetrics() ([]metrics.Metric, error) {
	return nil, nil
}

func (l *luajitInstance) ReleaseResources() error {
	return nil
}

func (l *luajitInstance) UpdateLibcInfo(ebpf interpreter.EbpfHandler, pid libpf.PID, info libc.LibcInfo) error {
	return nil
}
