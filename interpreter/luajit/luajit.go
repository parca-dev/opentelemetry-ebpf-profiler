// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Boilerplate stubs for LuaJIT implementation.

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import (
	"debug/elf"
	"errors"
	"fmt"
	"sync"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
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
}

type luajitInstance struct {
	interpreter.InstanceStubs
	rm         remotememory.RemoteMemory
	protos     map[libpf.Address]*proto
	jitRegions regionMap
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

	g2Traces uint16
}

var (
	_ interpreter.Data     = &luajitData{}
	_ interpreter.Instance = &luajitInstance{}
)

func (d *luajitData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address,
	rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	return &luajitInstance{}, nil
}

func (d *luajitData) Unload(_ interpreter.EbpfHandler) {}

func (l *luajitInstance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return nil
}

func GetLoader(_ Config) interpreter.Loader {
	return interpreter.NewLoader(loader, []interpreter.InterpreterResource{
		{MapName: BPFMapName},
	})
}

func loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	return nil, nil
}

const (
	// minInterpreterSize is the lower bound for the size of the stack delta
	// corresponding to the interpreter.
	minInterpreterSize = 10_000
)

// LuaJIT's interpreter isn't a function, it's a raw chunk of assembly code with direct threaded
// jumps at end of each opcode. The public entrypoints (lua_pcall/lua_resume) call the lj_vm_pcall
// function at the end of this blob which set up the interpreter and starts executing.
// Even though it's not a normal function an eh_frame entry is created for it, it's really
// big and has a somewhat unique FDE we can pick out. We could tighten this up by looking for
// direct jumps to the start of the interpreter (one can be found lj_dispatch_update) but we'd
// still need to consult the stack deltas to get the end of the interpreter.
func extractInterpreterBounds(machine elf.Machine, intervals sdtypes.IntervalData, param int32) (util.Range,
	error) {
DeltasLoop:
	for i, bk := range intervals.Blocks {
		for j, d := range bk.Deltas {
			var next *sdtypes.StackDelta
			var nextBk *sdtypes.BasicBlock
			if j < len(bk.Deltas)-1 {
				next = &bk.Deltas[j+1]
				nextBk = bk
			} else {
				for nextI := i + 1; nextI < len(intervals.Blocks); nextI += 1 {
					nextBk = intervals.Blocks[nextI]
					if len(nextBk.Deltas) != 0 {
						next = &nextBk.Deltas[0]
						break
					}
				}
			}
			if next == nil {
				break DeltasLoop
			}
			dAddr := bk.Start + uint64(d.Offset)
			nextAddr := nextBk.Start + uint64(next.Offset)
			if nextAddr < dAddr || nextAddr-dAddr <= minInterpreterSize {
				continue
			}

			// The first case covers x86 w/ dwarf and old versions of luajit ARM that used dwarf and
			// the second covers more recent arm versions that use frame pointers.
			if (d.Info.BaseReg == support.UnwindRegSp && d.Info.Param == param) ||
				(machine == elf.EM_AARCH64 && d.Info.BaseReg == support.UnwindRegFp && d.Info.Param == 16) {
				return util.Range{Start: dAddr, End: nextAddr}, nil
			}
		}
	}
	return util.Range{}, errors.New("failed to find interpreter range")
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
		fileID := support.LJJitMarker << 32
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
		fileID := support.LJJitMarker<<32 | spadjust
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

			stackDelta := uint64(t.spadjust) + uint64(cframeSizeJIT)
			// If this is a side trace, we need to add the spadjust of the root trace but
			// only if they are different.
			//https://github.com/openresty/luajit2/blob/7952882d/src/lj_gdbjit.c#L597
			if t.root != 0 && traces[t.root].spadjust != t.spadjust {
				stackDelta += uint64(traces[t.root].spadjust) + uint64(cframeSizeJIT)
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
		funcName, err := pt.getFunctionName(callerPC)
		if err != nil {
			return err
		}
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
		return fmt.Errorf("unrecognized LuaJIT frame kind: %d", ljkind)
	}

	return nil
}
