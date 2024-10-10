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

// This file contains the code and map definitions for the Luajit tracer

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"
#include "luajit.h"

bpf_map_def SEC("maps") luajit_procs = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(pid_t),
  .value_size = sizeof(LuaJITProcInfo),
  .max_entries = 1024,
};

// The number of LuaJIT frames to unwind per frame-unwinding eBPF program. 
#define FRAMES_PER_WALK_LUAJIT_STACK 25

#if defined(__x86_64__)
#define DISPATCH r14
#elif defined(__aarch64__)
#define DISPATCH r7
#endif

// Non error checking bpf read, used sparingly for reading sections of the stack after 
// we've established we can read neighboring memory.
#define deref(o) ({ void*__val; bpf_probe_read_user(&__val, sizeof(void*), o); __val; })

typedef signed long long    intptr_t;

#define L_PART_OFFSET 0x10
#define CFRAME_SIZE_JIT 0x60

// The offset of the "glref" field in the L struct has never changed in the history of LuaJIT so hard code it.
#define L_G_OFFSET 0x10

///////// BEGIN code copied from luajit2 sources.

#define LJ_FR2 1
#define LJ_GCVMASK		(((u64)1 << 47) - 1)

enum {
  FRAME_LUA, FRAME_C, FRAME_CONT, FRAME_VARG,
  FRAME_LUAP, FRAME_CP, FRAME_PCALL, FRAME_PCALLH
};
#define FRAME_TYPE	3
#define FRAME_P			4
#define FRAME_TYPEP		(FRAME_TYPE|FRAME_P)


// Use luajit2 style macros in case we come back and want to implement
// support for luajit's compressed 32 bit pointer/value scheme, idea 
// being we'd implement all the macros for both systems and build 
// two unwinders. Also the macros should make the code look familiar to
// those familiar w/ luajit.
#define bc_a(i)		((u32)(((i)>>8)&0xff))
#define gcval(o) ((void*) ((u64)(deref(o)) & LJ_GCVMASK))
#define frame_gc(f)		(gcval((f)-1))
#define obj2gco(v) ((void *)(v))
#define frame_type(f)		  (f & FRAME_TYPE)
#define frame_typep(f)		(f & FRAME_TYPEP)
#define frame_islua(f)		(frame_type(f) == FRAME_LUA)
#define frame_isvarg(f)		(frame_typep(f) == FRAME_VARG)
#define frame_sized(fval)		(((s32)fval) & ~FRAME_TYPEP)
#define frame_prevd(f,fval) ((TValue *)((char *)(f)-frame_sized(fval)))
#define frame_func(f)		(frame_gc(f))
#define frame_pc(f)     (const u32*)(f)
#define frame_iscont(f)		(frame_typep(f) == FRAME_CONT)

#define CFRAME_RESUME		1
#define CFRAME_UNWIND_FF	2  /* Only used in unwinder. */
#define CFRAME_RAWMASK		(~(intptr_t)(CFRAME_RESUME|CFRAME_UNWIND_FF))
#define cframe_raw(cf)		((void *)((intptr_t)(cf) & CFRAME_RAWMASK))
#define CFRAME_OFS_PC		(3*8)
#define CFRAME_OFS_L		(2*8)
#define cframe_pc_addr(cf) (void*)(((char *)(cf)) + CFRAME_OFS_PC)
#define cframe_L_addr(cf)  (void*)(((char *)(cf)) + CFRAME_OFS_L)

/* Invalid bytecode position. */
#define NO_BCPOS	(~(u32)0)
#define FF_LUA		0

///////// END code copied from luajit2 sources.

// lj_debug_framepc for a function.  There's no easy way to look at this, basically 
// there's a bunch of places the return address is stored depending on the frame 
// type.
// https://github.com/openresty/luajit2/blob/7952882d/src/lj_debug.c#L53
static inline __attribute__((__always_inline__))
ErrorCode lj_debug_framepc(PerCPURecord *record, void *fn, u32 *startpc, TValue *nextframe, u32 *pc) {
  LJFuncPart *f = &record->luajitUnwindScratch.f;
  if (bpf_probe_read_user(f, sizeof(LJFuncPart), (void***)fn + 1)) {
    return ERR_LUAJIT_FRAME_READ;
  }
  if (f->ffid != FF_LUA) {  /* Cannot derive a PC for non-Lua functions. */
     DEBUG_PRINT("lj: non-lua function %lx", (unsigned long)f->ffid);
     *pc = NO_BCPOS;
     return ERR_OK;
  }
  const u32 *ins;
  if (nextframe == NULL) {  /* Lua function on top. */
    void *cf = cframe_raw(record->luajitUnwindScratch.L.cframe);
    if (cf == NULL) {
      DEBUG_PRINT("lj: cframe null");
      *pc = NO_BCPOS;
      return ERR_OK;
    }
    void *pc_addr = cframe_pc_addr(cf);
    void *L_addr = cframe_L_addr(cf);
    void *L_ptr;
    if (bpf_probe_read_user(&ins, sizeof(void*), pc_addr)) {
      DEBUG_PRINT("lj: pc_addr read failed");
      return ERR_LUAJIT_FRAME_READ;
    }
    if (bpf_probe_read_user(&L_ptr, sizeof(void*), L_addr)) {
      DEBUG_PRINT("lj: L_addr read failed");
      return ERR_LUAJIT_FRAME_READ;
    }
    if (ins == (void*)record->luajitUnwindState.L_ptr || ins == NULL) {
     DEBUG_PRINT("lj: ins == L or NULL");
     *pc = NO_BCPOS;
     return ERR_OK;
    }
  } else {
    TValue frame_val;
    if (bpf_probe_read_user(&frame_val, sizeof(void*), nextframe)) {
      DEBUG_PRINT("lj: frame_val 1 read failed");
      return ERR_LUAJIT_FRAME_READ;
    }
    if (frame_islua(frame_val)) {
      ins = frame_pc(frame_val);
    } else if (frame_iscont(frame_val)) {
      //ins = frame_contpc(nextframe);
      if (bpf_probe_read_user(&frame_val, sizeof(void*), nextframe - 2)) {
        DEBUG_PRINT("lj: frame_val 2 read failed");
        return ERR_LUAJIT_FRAME_READ;
      }
      ins = frame_pc(frame_val);
    } else {
      /* Lua function below errfunc/gc/hook: find cframe to get the PC. */
      // NYI: This is an edge case that requires two unbounded loops
      DEBUG_PRINT("lj: lua function below errfunc/gc/hook");
      *pc = NO_BCPOS;
      return ERR_OK;
    }
  }
  *pc = ins - startpc - 1;
  return ERR_OK;
}

static inline __attribute__((__always_inline__))
ErrorCode lj_record_frame(PerCPURecord *record, TValue *frame, TValue* nextframe) {
  u32 pc;
  void *fn = frame_func(frame);
  // EBPF version of funcproto macro
  // Get GCproto pointer by getting pc pointer and backing up sizeof(GCproto)
  // (gdb) p &((GCfuncL*)0)->pc
  // $1 = (MRef *) 0x20
  void *bytecodep;
  if (bpf_probe_read_user(&bytecodep, sizeof(void*), fn + 0x20)) {
    return ERR_LUAJIT_FRAME_READ;
  }
  // The bytecode is allocated after the GCproto.
  // (gdb) p/x sizeof(GCproto)
  // $4 = 0x68
  void *pt = (char*)bytecodep - 0x68;

  ErrorCode err = lj_debug_framepc(record, fn, bytecodep, nextframe, &pc);
  if (err) {
    return err;
  }
  DEBUG_PRINT("lj: record frame %lx:%u", (unsigned long)pt, pc);
  return _push(&record->trace, (u64)pt, pc, FRAME_MARKER_LUAJIT);
}

// See:
// https://github.com/openresty/luajit2/blob/7952882d/src/lj_frame.h#L33
static inline __attribute__((__always_inline__))
ErrorCode lj_prev_frame(PerCPURecord *record, TValue frame_val, bool *skip) {
  TValue *frame = record->luajitUnwindState.frame;
  if (frame_islua(frame_val)) {
      // This is the EBPF version of the frame_prevl macro.
      int delta = 1+LJ_FR2;
      u32 prevIns;
      if (bpf_probe_read_user(&prevIns, sizeof(u32), (u32*)(frame_val) - 1)) {
        return ERR_LUAJIT_FRAME_READ;
      }
      delta += bc_a(prevIns);
      record->luajitUnwindState.frame = frame - delta;
  } else {
      if (frame_isvarg(frame_val)) {
        *skip = true; /* Skip vararg pseudo-frame. */
      }
      record->luajitUnwindState.frame = frame_prevd(frame, frame_val);
  }
  return ERR_OK;
}

// walk_luajit_stack walks the luajit stack by inspecting the frame values 
// and finding ones that indicate a function call frame. Code inspired by
// lj_debug_frame.
// https://github.com/openresty/luajit2/blob/7952882d/src/lj_debug.c#L25
static inline __attribute__((__always_inline__))
ErrorCode walk_luajit_stack(PerCPURecord *record, const LuaJITProcInfo *lj_info, 
                          int* next_unwinder) {
  bool skip = false;
  LJState *L = &record->luajitUnwindScratch.L;
  TValue *nextframe = NULL;
  TValue *bot = L->stack + 1;
  #pragma unroll
  for (int i = 0; i < FRAMES_PER_WALK_LUAJIT_STACK; i++) {
    TValue *frame = (TValue*)(record->luajitUnwindState.frame);
    if (frame <= bot) {
      // Need to clear this if we have more than one LuaJIT call on the stack.
      record->luajitUnwindState.frame = NULL;
      // We have processed all frames, send LuaJIT sentinel end frame.
      // Store G_addr in sentinel frame line slot to make it easy for 
      // unwinder to check that JIT unwinding stack delta maps are current.
      ErrorCode error = _push(&record->trace, (u64)0, (u64)record->luajitUnwindScratch.G_to_report, FRAME_MARKER_LUAJIT);
      if (error) {
        return error;
      }
      DEBUG_PRINT("lj: end lua frame");
      return ERR_OK;
    }
    if (frame_gc(frame) == obj2gco(record->luajitUnwindState.L_ptr)) {
      skip = true; /* Skip dummy frames. See lj_err_optype_call(). */
    }    
    TValue frame_val;
    if (bpf_probe_read_user(&frame_val, sizeof(TValue), frame)) {
      return ERR_LUAJIT_FRAME_READ;
    }
    if (!frame_islua(frame_val)) {
      skip = true;
    }
    if (!skip) {
        ErrorCode err = lj_record_frame(record, frame, nextframe);
        if (err) {
            DEBUG_PRINT("lj: walk_lua_stack: lua_get_funcdata=%d", err);
            return err;
        }
    } else {
        skip = false;
    }   
    nextframe = frame;
    ErrorCode err = lj_prev_frame(record, frame_val, &skip);
    if (err) {
      return err;
    }
  }

  // We exhausted loops, come back for more!
  *next_unwinder = PROG_UNWIND_LUAJIT;

  return ERR_OK;
}

static inline __attribute__((__always_inline__))
ErrorCode find_frame(struct pt_regs *ctx, PerCPURecord *record, const LuaJITProcInfo *info) {
  u64 G_ptr=0;
  u64 L_ptr;
  bool unMappedPC = false;
  UnwindState *state = &record->state;
  u32 high = (u32)(state->text_section_id >> 32);
  
  // The initial state is for the entire anonymous/executable memory range to be mapped to
  // our unwinder with a token file ID.  Then we fire a pid event which will call SynchronizeMappings
  // in the HA which will overlay the big anonymous/executable memory range with the actual mappings
  // for each trace with a stack adjustment stored in the low bits. 
  if (high == LUAJIT_JIT_FILE_ID) {
    record->luajitUnwindState.is_jit = true;
    //https://github.com/openresty/luajit2/blob/7952882d/src/lj_frame.h#L178
    u64 delta = info->cframe_size_jit;
    u32 spadjust = (u32)state->text_section_id;
    delta += spadjust;
    state->sp += delta;
    u64 frame[2];
    if (bpf_probe_read_user(frame, sizeof(frame), (void*)(state->sp - sizeof(frame)))) {
      DEBUG_PRINT("lj: failed to read frame");
      increment_metric(metricID_UnwindLuaJITErrNoContext);
      return ERR_LUAJIT_READ_LUA_CONTEXT;
    }

    state->fp = frame[0];
    u64 pc = state->pc;
    (void)pc; // appease non-debug builds
    state->pc = frame[1];
    state->return_address = true;
    DEBUG_PRINT("lj: unwound JIT frame (%lx) to pc:%lx, sp:%lx", (unsigned long)pc, (unsigned long)state->pc, (unsigned long)state->sp);

    // Its very common for the stack adjustment to be zero so even for known traces we'll be sending
    // this report_pid signal a lot.  We cache the traces in the HA and the report mechanism has a 
    // rate limiter so I'm assuming this is fine for now.
    if (state->text_section_bias == 0) {
      DEBUG_PRINT("lj: unwinding unmapped JIT frame");
      report_pid(ctx, record->trace.pid, RATELIMIT_ACTION_DEFAULT);
      unMappedPC = true;

      // If top frame isn't luajit we can't rely on the register holding the DISPATCH table, but once
      // we propagate G to the HA text_section_bias will be set to the G pointer and we can
      // pull cur_L from that. So this is just a bootstrap crutch that just has to work once.
      G_ptr = state->DISPATCH - info->g2dispatch;
      
      if (bpf_probe_read_user(&L_ptr, sizeof(void*), (void*)(G_ptr + info->cur_L_offset))) {
        DEBUG_PRINT("lj: failed to read G->cur_L %lx", (unsigned long)(G_ptr + info->cur_L_offset));
        increment_metric(metricID_UnwindLuaJITErrNoContext);
        return ERR_LUAJIT_READ_LUA_CONTEXT;
      }
    } else {
      G_ptr = state->text_section_bias;
      DEBUG_PRINT("lj: unwinding trace mapped JIT frame %lx: delta: %u", (unsigned long)G_ptr, spadjust);
      if (bpf_probe_read_user(&L_ptr, sizeof(void*), (void*)(G_ptr + info->cur_L_offset))) {
        DEBUG_PRINT("lj: failed to read G->cur_L %lx", (unsigned long)((void*)(G_ptr + info->cur_L_offset)));
        increment_metric(metricID_UnwindLuaJITErrNoContext);
        return ERR_LUAJIT_READ_LUA_CONTEXT;
      }
    }
  } else {
    // PC is in interpter, L is pretty reliably at constant offset from SP.
    if (bpf_probe_read_user(&L_ptr, sizeof(void*), (void*)(state->sp + L_G_OFFSET))) {
      DEBUG_PRINT("lj: failed to read stack");
      increment_metric(metricID_UnwindLuaJITErrNoContext);
      return ERR_LUAJIT_READ_LUA_CONTEXT;
    }
  }

  LJScratchSpace *scr = &record->luajitUnwindScratch;
  if (bpf_probe_read_user(&scr->L, sizeof(LJState), (char*)L_ptr+L_PART_OFFSET)) {
    DEBUG_PRINT("lj: bad L: failed to read L from: %lx", (unsigned long)L_ptr);
    increment_metric(metricID_UnwindLuaJITErrNoContext);
    return ERR_LUAJIT_READ_LUA_CONTEXT;
  }

  // If we came through interpreter we won't have G yet.
  if (G_ptr == 0) {
    G_ptr = (u64)scr->L.glref;
  }

  if (bpf_probe_read_user(&scr->G, sizeof(LJGlobalPart), (void*)(G_ptr + info->cur_L_offset))) {
    DEBUG_PRINT("lj: bad G picked up from L: failed to read G->cur_L: %lx, %lx", (unsigned long)G_ptr, (unsigned long)info->cur_L_offset);
    increment_metric(metricID_UnwindLuaJITErrNoContext);
    return ERR_LUAJIT_READ_LUA_CONTEXT;
  }

  if (L_ptr != scr->G.cur_L) {
    DEBUG_PRINT("lj: L context check failed: %lx != %lx", (unsigned long)L_ptr, (unsigned long)scr->G.cur_L);
    increment_metric(metricID_UnwindLuaJITErrLMismatch);
    return ERR_LUAJIT_L_MISMATCH;
  }

  DEBUG_PRINT("lj: L context: %lx", (unsigned long)L_ptr);
  record->luajitUnwindState.L_ptr = L_ptr;

  // The JIT doesn't update base as it goes but it does update G.jit_base.
  if (high == LUAJIT_JIT_FILE_ID) {
    record->luajitUnwindState.frame = scr->G.jit_base - 1;
  } else {
    record->luajitUnwindState.frame = scr->L.base - 1;
  }

  // If G is not null we'll send it to through to symbolizer which will record it for SynchronizeMappings 
  // to use to make sure the JIT mappings are up to date.
  scr->G_to_report = unMappedPC ? G_ptr : 0;

  return ERR_OK;
}

SEC("perf_event/unwind_luajit")
int unwind_luajit(struct pt_regs *ctx) {
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  UnwindState *state = &record->state;
  int unwinder = get_next_unwinder_after_interpreter(record);
  ErrorCode error = ERR_OK;
  u32 pid = record->trace.pid;
  LuaJITProcInfo *info = bpf_map_lookup_elem(&luajit_procs, &pid);

  if (!info) {
    DEBUG_PRINT("lj: no LuaJIT introspection data");
    error = ERR_LUAJIT_NO_PROC_INFO;
    increment_metric(metricID_UnwindLuaJITErrNoProcInfo);
    goto exit;
  }
  increment_metric(metricID_UnwindLuaJITAttempts);

  if (record->luajitUnwindState.frame == 0) {  
    if ((error = find_frame(ctx, record, info))) {
      goto exit;
    }
  }

  if ((error = walk_luajit_stack(record, info, &unwinder))) {
    goto exit;
  }

  if (record->luajitUnwindState.is_jit) {
    // Interpreter frames unwind naturally, we had to poke sp/pc for JIT frames
    // so we need to call this for the native unwinder to continue over them.
    if ((error = resolve_unwind_mapping(record, &unwinder)) != ERR_OK) {
      unwinder = PROG_UNWIND_STOP;
      goto exit;
    }
  }
  
exit:
  state->unwind_error = error;
  tail_call(ctx, unwinder);
  return -1;
}
