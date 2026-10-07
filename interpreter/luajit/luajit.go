// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Boilerplate stubs for LuaJIT implementation.

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import (
	"debug/elf"
	"errors"
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/host"
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

	// Currently mapped prefixes for entire memory regions
	prefixes map[regionKey][]lpm.Prefix

	cycle int
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
	// TODO - When the full LuaJIT interpreter lands, this will process the "g" objects
	// that we learned about from the eBPF side, and add the traces they contain to the
	// interpreter mapping. Until then, it is a no-op.
	return nil
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
		// TODO -- The unwinder backend has reported the location of
		// the "g" variable for the current VM.
		// This will be handled in a future PR, when we submit the
		// unwinder code. Since it's not strictly related to symbolization, we omit it
		// for now.
		return nil
	default:
		return fmt.Errorf("unrecognized LuaJIT frame kind: %d", ljkind)
	}

	return nil
}
