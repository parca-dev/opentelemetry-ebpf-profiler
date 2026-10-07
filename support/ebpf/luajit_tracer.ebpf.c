// This file contains the code and map definitions for the LuaJIT tracer

#include "bpfdefs.h"
#include "errors.h"
#include "luajit.h"
#include "tracemgmt.h"
#include "types.h"

struct luajit_procs_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, LuaJITProcInfo);
  __uint(max_entries, 1024);
} luajit_procs SEC(".maps");

// The number of LuaJIT frames to unwind per frame-unwinding eBPF program.
#define LJ_FRAMES_PER_WALK_LUAJIT_STACK 15

// Non error checking bpf read, used sparingly for reading sections of the stack after
// we've established we can read neighboring memory.
#define lj_deref(o)                                                                                \
  ({                                                                                               \
    void *__val;                                                                                   \
    bpf_probe_read_user(&__val, sizeof(void *), o);                                                \
    __val;                                                                                         \
  })

#define LJ_L_PART_OFFSET 0x10
// (gdb) p/x sizeof(GCproto)
// $4 = 0x68
#define LJ_GCPROTO_SIZE  0x68

// This is L offset into interpreter stack frames.
#define LJ_L_STACK_OFFSET 0x10

///////// BEGIN code copied from luajit2 sources.

#define LJ_FR2     1
#define LJ_GCVMASK (((u64)1 << 47) - 1)
enum {
  LJ_FRAME_LUA,
  LJ_FRAME_C,
  LJ_FRAME_CONT,
  LJ_FRAME_VARG,
  LJ_FRAME_LUAP,
  LJ_FRAME_CP,
  LJ_FRAME_PCALL,
  LJ_FRAME_PCALLH
};
#define LJ_FRAME_TYPE  3
#define LJ_FRAME_P     4
#define LJ_FRAME_TYPEP (LJ_FRAME_TYPE | LJ_FRAME_P)

enum { LJ_CONT_TAILCALL, LJ_CONT_FFI_CALLBACK }; /* Special continuations. */

// Use luajit2 style macros in case we come back and want to implement
// support for luajit's compressed 32 bit pointer/value scheme, idea
// being we'd implement all the macros for both systems and build
// two unwinders. Also the macros should make the code look familiar to
// those familiar w/ luajit.
#define bc_a(i)                  ((u32)(((i) >> 8) & 0xff))
#define gcval(o)                 ((void *)((u64)(lj_deref(o)) & LJ_GCVMASK))
#define lj_frame_gc(f)           (gcval((f)-1))
#define obj2gco(v)               ((void *)(v))
#define lj_frame_type(f)         (f & LJ_FRAME_TYPE)
#define lj_frame_typep(f)        (f & LJ_FRAME_TYPEP)
#define lj_frame_islua(f)        (lj_frame_type(f) == LJ_FRAME_LUA)
#define lj_frame_isvarg(f)       (lj_frame_typep(f) == LJ_FRAME_VARG)
#define lj_frame_isc(f)          (lj_frame_type(f) == LJ_FRAME_C)
#define lj_frame_sized(fval)     (((s32)fval) & ~LJ_FRAME_TYPEP)
#define lj_frame_prevd(f, fval)  ((LJTValue *)((char *)(f)-lj_frame_sized(fval)))
#define lj_frame_func(f)         (lj_frame_gc(f))
#define lj_frame_pc(f)           (const u32 *)(f)
#define lj_frame_iscont(f)       (lj_frame_typep(f) == LJ_FRAME_CONT)
#define lj_frame_contv(f)        ((u64)(lj_deref((f)-3)))
#define lj_frame_iscont_fficb(f) (lj_frame_contv(f) == LJ_CONT_FFI_CALLBACK)

#define restorestack(L, n) ((LJTValue *)((char *)L.stack + (n)))

#if defined(__x86_64__)
  #define LJ_CFRAME_OFS_PREV (4 * 8)
  #define LJ_CFRAME_OFS_PC   (3 * 8)
  #define LJ_CFRAME_OFS_NRES (2 * 4)
  #define LJ_CFRAME_OFS_L    (2 * 8)
#elif defined(__aarch64__)
  #define LJ_CFRAME_OFS_PREV 0
  #define LJ_CFRAME_OFS_NRES 40
  #define LJ_CFRAME_OFS_L    16
  #define LJ_CFRAME_OFS_PC   8
#endif

#define LJ_CFRAME_RESUME        1
#define LJ_CFRAME_UNWIND_FF     2 /* Only used in unwinder. */
#define LJ_CFRAME_RAWMASK       (~(s64)(LJ_CFRAME_RESUME | LJ_CFRAME_UNWIND_FF))
#define lj_cframe_nres_addr(cf) (s32 *)(((char *)(cf)) + LJ_CFRAME_OFS_NRES)
#define lj_cframe_raw(cf)       ((void *)((s64)(cf) & LJ_CFRAME_RAWMASK))
#define lj_cframe_pc_addr(cf)   (void *)(((char *)(cf)) + LJ_CFRAME_OFS_PC)
#define lj_cframe_L_addr(cf)    (void *)(((char *)(cf)) + LJ_CFRAME_OFS_L)
#define lj_cframe_prev(cf)      lj_deref((void **)(((char *)(cf)) + LJ_CFRAME_OFS_PREV))

/* Invalid bytecode position. */
#define NO_BCPOS (~(u32)0)
#define FF_LUA   0

///////// END code copied from luajit2 sources.

static EBPF_INLINE LJTValue *lj_frame_prevl(LJTValue *f, LJTValue frame_val)
{
  // This is the EBPF version of the lj_frame_prevl macro.
  // #define frame_prevl(f)		((f) - (1+LJ_FR2+bc_a(frame_pc(f)[-1])))
  int delta = 1 + LJ_FR2;
  u32 prevIns;
  bpf_probe_read_user(&prevIns, sizeof(u32), (u32 *)(frame_val)-1);
  delta += bc_a(prevIns);
  return f - delta;
}

// lj_debug_framepc for a function.  There's no easy way to look at this, basically
// there's a bunch of places the return address is stored depending on the frame
// type.
// https://github.com/openresty/luajit2/blob/7952882d/src/lj_debug.c#L53
static EBPF_INLINE ErrorCode lj_debug_framepc(
  struct pt_regs *ctx, PerCPURecord *record, void *fn, u32 *startpc, LJTValue *prevframe, u32 *pc)
{
  LJFuncPart *func = &record->luajitUnwindScratch.f;
  if (bpf_probe_read_user(func, sizeof(LJFuncPart), (void **)fn + 1)) {
    return ERR_LUAJIT_FRAME_READ;
  }
  if (func->ffid != FF_LUA) { /* Cannot derive a PC for non-Lua functions. */
    DEBUG_PRINT("lj: non-lua function %lx", (unsigned long)func->ffid);
    *pc = NO_BCPOS;
    return ERR_OK;
  }
  const u32 *ins = NULL;
  if (prevframe == NULL) { /* Lua function on top. */
    bool leaf_in_lua = (record->initialUnwinder == PROG_UNWIND_LUAJIT);
    DEBUG_PRINT("lj: leaf_in_lua: %d", leaf_in_lua);
    if (leaf_in_lua) {
#if defined(__x86_64__)
      ins = (u32 *)ctx->bx;
#elif defined(__aarch64__)
      ins = (u32 *)ctx->regs[21];
#else
  #error unsupported architecture
#endif
    } else {
      void *cf = lj_cframe_raw(record->luajitUnwindScratch.L.cframe);
      if (cf == NULL) {
        DEBUG_PRINT("lj: cframe null");
        *pc = NO_BCPOS;
        return ERR_OK;
      }
      void *pc_addr = lj_cframe_pc_addr(cf);
      void *L_addr  = lj_cframe_L_addr(cf);
      void *L_ptr;
      if (bpf_probe_read_user(&ins, sizeof(void *), pc_addr)) {
        DEBUG_PRINT("lj: pc_addr read failed");
        return ERR_LUAJIT_FRAME_READ;
      }
      if (bpf_probe_read_user(&L_ptr, sizeof(void *), L_addr)) {
        DEBUG_PRINT("lj: L_addr read failed");
        return ERR_LUAJIT_FRAME_READ;
      }
      if (ins == (void *)record->luajitUnwindState.L_ptr || ins == NULL) {
        DEBUG_PRINT("lj: ins == L or NULL");
        *pc = NO_BCPOS;
        return ERR_OK;
      }
    }
  } else {
    LJTValue frame_val;
    if (bpf_probe_read_user(&frame_val, sizeof(void *), prevframe)) {
      DEBUG_PRINT("lj: frame_val 1 read failed");
      return ERR_LUAJIT_FRAME_READ;
    }
    if (lj_frame_islua(frame_val)) {
      ins = lj_frame_pc(frame_val);
    } else if (lj_frame_iscont(frame_val)) {
      // ins = lj_frame_contpc(nextframe);
      if (bpf_probe_read_user(&frame_val, sizeof(void *), prevframe - 2)) {
        DEBUG_PRINT("lj: frame_val 3 read failed");
        return ERR_LUAJIT_FRAME_READ;
      }
      ins = lj_frame_pc(frame_val);
    } else {
      /* Lua function below errfunc/gc/hook: find cframe to get the PC. */
      DEBUG_PRINT("lj: lua function below errfunc/gc/hook");
      // This code is commented out because we haven't figured out how to test it.
      //     void *cf = lj_cframe_raw(record->luajitUnwindScratch.L.cframe);
      //     LJTValue *f = record->luajitUnwindScratch.L.base-1;
      // #define LJ_CFRAME_SEARCH_LOOPS 5
      // #define LJ_CFRAME_SEARCH_LOOPS2 5

      // #pragma unroll
      //     for (int i = 0; i < LJ_CFRAME_SEARCH_LOOPS; i++) {
      //       if (cf == NULL) {
      //         *pc = NO_BCPOS;
      //         return ERR_OK;
      //       }
      //       #pragma unroll
      //       for (int j = 0; j < LJ_CFRAME_SEARCH_LOOPS2; j++) {
      //         s32 *nresp = lj_cframe_nres_addr(cf);
      //         s32 nres;
      //         bpf_probe_read_user(&nres, sizeof(s32), nresp);
      //         if (f >= restorestack(record->luajitUnwindScratch.L, -nres))
      //           break;
      //         cf = lj_cframe_raw(lj_cframe_prev(cf));
      //         if (cf == NULL) {
      //           *pc = NO_BCPOS;
      //           return ERR_OK;
      //         }
      //       }
      //       if (f < prevframe)
      //         break;
      //       if (bpf_probe_read_user(&frame_val, sizeof(void*), prevframe)) {
      //         DEBUG_PRINT("lj: frame_val 4 read failed");
      //         return ERR_LUAJIT_FRAME_READ;
      //       }
      //       if (lj_frame_islua(frame_val)) {
      //         f = lj_frame_prevl(f, frame_val);
      //       } else {
      //         if (lj_frame_isc(frame_val) || (lj_frame_iscont(frame_val) &&
      //         lj_frame_iscont_fficb(f)))
      //           cf = lj_cframe_raw(lj_cframe_prev(cf));
      //         f = lj_frame_prevd(f,frame_val);
      //       }
      //     }
      //     const u32 **insp = lj_cframe_pc_addr(cf);
      //     if (bpf_probe_read_user(&ins, sizeof(void*), insp)) {
      //       DEBUG_PRINT("lj: ins read failed");
      //       return ERR_LUAJIT_FRAME_READ;
      //     }
      if (!ins) {
        *pc = NO_BCPOS;
        return ERR_OK;
      }
    }
  }
  // startpc can be for a different function if we land on instructions where things aren't synced.
  // For instance the PC is up to date on the stack but jit_base wasn't updated yet.
  DEBUG_PRINT("lj: ins: %llx, startpc: %llx", (u64)ins, (u64)startpc);
  if (ins < startpc) {
    DEBUG_PRINT("lj: ins < startpc, setting *pc = NO_BCPOS");
    *pc = NO_BCPOS;
    return ERR_OK;
  }
  u64 pcval = (u64)(ins - startpc) - 1;
  if (pcval > 0xFFFFFFFF) {
    DEBUG_PRINT("lj: PC too big, should fit in 32 bits: %llx", pcval);
    return ERR_LUAJIT_FRAME_READ;
  }
  *pc = (u32)pcval;
  DEBUG_PRINT("ins, startpc good: setting *pc = %llx", (u64)*pc);
  return ERR_OK;
}

// For Lua we need the caller and callee to process a frame.
// The callee_pt is a pointer to the GCproto of the function being called, the
// callee_pc is an index into its bytecode. The caller_pt is the
// GCproto of the calling function and the caller_pc is the index into its
// bytecode which we will walk backwards in userland to figure out a name for the
// callee. The callee_pc is for information purposes only, so the user can see where
// execution was.
static EBPF_INLINE ErrorCode lj_push_frame(
  UnwindState *state, Trace *trace, u64 callee_pt, u64 caller_pt, u32 callee_pc, u32 caller_pc)
{
  u64 *data =
    push_frame(state, trace, FRAME_MARKER_LUAJIT, FRAME_FLAG_PID_SPECIFIC, LUAJIT_NORMAL_FRAME, 3);
  if (!data)
    return ERR_STACK_LENGTH_EXCEEDED;
  data[0] = ((u64)callee_pc << 32) | caller_pc;
  data[1] = caller_pt;
  data[2] = callee_pt;

  return ERR_OK;
}

static EBPF_INLINE ErrorCode lj_record_frame(
  struct pt_regs *ctx,
  PerCPURecord *record,
  LJTValue *frame,
  LJTValue frame_value,
  LJTValue *prevframe)
{
  LJScratchSpace *scr = &record->luajitUnwindScratch;
  if (lj_frame_isvarg(frame_value)) {
    DEBUG_PRINT("lj: vararg frame");
    return ERR_OK; /* Skip vararg frames. */
  }
  if (lj_frame_gc(frame) == obj2gco(record->luajitUnwindState.L_ptr)) {
    DEBUG_PRINT("lj: skip dummy frame");
    return ERR_OK; /* Skip dummy frames. See lj_err_optype_call(). */
  }
  void *fn      = lj_frame_func(frame);
  LJFuncPart *f = &scr->f;
  // +1 to skip the 8 byte GCHeader
  if (bpf_probe_read_user(f, sizeof(LJFuncPart), (void **)fn + 1)) {
    return ERR_LUAJIT_FRAME_READ;
  }

  if (f->ffid != FF_LUA) {
    DEBUG_PRINT("lj: lj_record_frame: ffi function %lx", (unsigned long)f->ffid);
    // We can't derive a name for this function, so we'll just emit a pseudo frame.
    u64 *data = push_frame(
      &record->state,
      &record->trace,
      FRAME_MARKER_LUAJIT,
      FRAME_FLAG_PID_SPECIFIC,
      LUAJIT_FFI_FUNC,
      1);
    if (!data)
      return ERR_STACK_LENGTH_EXCEEDED;
    data[0] = frame_value;
  }

  u32 *start_ip = (u32 *)f->pc;
  // The bytecode is allocated after the GCproto.
  void *proto   = (char *)f->pc - LJ_GCPROTO_SIZE;

  u32 pc;
  ErrorCode err = lj_debug_framepc(ctx, record, fn, start_ip, prevframe, &pc);
  if (err) {
    DEBUG_PRINT("lj: lj_debug_framepc err %u", err);
    return err;
  }
  if (pc == NO_BCPOS) {
    DEBUG_PRINT("lj: no bcpos");
    pc = 0xffffff;
  }
  // Top frame, we can't emit anything yet because we don't know the caller PC but stash callee_pc
  // for next time.
  if (record->luajitUnwindState.prevframe == NULL) {
    goto exit;
  }

  DEBUG_PRINT("lj: record frame callee %lx:%u", (unsigned long)scr->prev_proto, scr->prev_pc);
  DEBUG_PRINT("lj: record frame caller %lx:%u", (unsigned long)proto, pc);
  err = lj_push_frame(
    &record->state, &record->trace, (u64)scr->prev_proto, (u64)proto, scr->prev_pc, pc);
exit:
  scr->prev_proto = proto;
  scr->prev_pc    = pc;
  return err;
}

// See:
// https://github.com/openresty/luajit2/blob/7952882d/src/lj_frame.h#L33
static EBPF_INLINE ErrorCode lj_prev_frame(PerCPURecord *record, LJTValue frame_val)
{
  LJTValue *frame = record->luajitUnwindState.frame;
  if (lj_frame_islua(frame_val)) {
    frame = lj_frame_prevl(frame, frame_val);
  } else {
    frame = lj_frame_prevd(frame, frame_val);
  }
  if (bpf_probe_read_user(&frame_val, sizeof(LJTValue), frame)) {
    return ERR_LUAJIT_FRAME_READ;
  }
  if (lj_frame_isvarg(frame_val)) {
    frame = lj_frame_prevd(frame, frame_val);
  }
  record->luajitUnwindState.frame = frame;
  return ERR_OK;
}

// Unwind a frame of native code; for example,
// a CFRAME at the C/Lua boundary.
//
// `is_jit`should be true if there is JITted code anywhere in the Lua code corresponding to this
// cframe.
static EBPF_INLINE ErrorCode
unwind_native_frame(const LuaJITProcInfo *info, UnwindState *state, bool is_jit)
{
  /* Interpreter frames unwind naturally, we need to poke sp/pc for JIT frames */
  /* so we need to call this for the native unwinder to continue over them. */
  /* https://github.com/openresty/luajit2/blob/7952882d/src/lj_frame.h#L178 */
  u32 spadjust;
  if (is_jit) {
    spadjust = (u32)state->text_section_id;
    if (spadjust == 0) {
      // Guess the default.
      spadjust = info->cframe_size_jit;
    }
  } else {
    spadjust = LUAJIT_CFRAME_SPACE;
  }

  state->sp += spadjust;
  u64 frame[2];
  if (bpf_probe_read_user(frame, sizeof(frame), (void *)(state->sp - sizeof(frame)))) {
    DEBUG_PRINT("lj: failed to read frame");
    increment_metric(metricID_UnwindLuaJITErrNoContext);
    return ERR_LUAJIT_READ_LUA_CONTEXT;
  }

  state->fp = frame[0];
  u64 pc    = state->pc;
  (void)pc; // appease non-debug builds
  state->pc             = frame[1];
  state->return_address = true;
  DEBUG_PRINT(
    "lj: unwound frame old pc:(%lx) to new pc:%lx, sp:%lx",
    (unsigned long)pc,
    (unsigned long)state->pc,
    (unsigned long)state->sp);

  return ERR_OK;
}

// walk_luajit_stack walks the luajit stack by inspecting the frame values
// and finding ones that indicate a function call frame. Code inspired by
// lj_debug_frame.
// https://github.com/openresty/luajit2/blob/7952882d/src/lj_debug.c#L25
static EBPF_INLINE ErrorCode walk_luajit_stack(
  struct pt_regs *ctx, PerCPURecord *record, const LuaJITProcInfo *info, int *next_unwinder)
{
  bool exitToNative = false;
  ErrorCode err;
  LJState *L          = &record->luajitUnwindScratch.L;
  LJTValue *prevframe = record->luajitUnwindState.prevframe;

  for (int i = 0; i < LJ_FRAMES_PER_WALK_LUAJIT_STACK; i++) {
    // A LuaJIT stack segment looks like this, where each cell is a TValue:
    // [ FUNC |  PC  | ARG1 | ARG2 | ARG3 | ..... ]
    //        ^      ^
    //        |      |
    //        |     BASE
    //        |
    //      frame
    //
    // In this diagram, `frame` points to our frame pointer (set below),
    // and BASE points to the bottom of the stack frame that is exposed to user code
    // (which can't access FUNC and PC).
    // Every time Lua calls into C, it sets L->base appropriately and then never
    // lets the C function read below it, so
    // it effectively has its own isolated stack. But in reality,
    // from the interpreter's perspective, these segments are concatenated into one array
    // pointed to by the L->stack object.
    //
    // For reasons of not-very-interesting internal implementation details,
    // BASE must always be two elements above the bottom of the stack,
    // even when the stack is logically empty. So whenever a new Lua state is created
    // (e.g. via luaL_newstate() or lua_newthread()), the interpreter
    // pushes two dummy values (see
    // https://github.com/luajit/luajit/blob/659a6169/src/lj_state.c#L168-L180).
    //
    // Thus, when `diff` (set below) is <= 2, we've actually unwound past the logical
    // root of the stack, which should never happen...
    LJTValue *frame = (LJTValue *)(record->luajitUnwindState.frame);

    long diff = frame - L->stack;
    DEBUG_PRINT("lj: distance to bot: %ld", diff);

    if (diff <= 2) {
      // Need to clear 'frame' if we have more than one LuaJIT call on the stack,
      // ie two different instances of LuaJIT, not sure if this happens in practice.
      // While conceptually this makes sense its kind of an edge case and
      // if we clear it we run into a situation where if we clear it and
      // encounter another luajit interpreter frame we'll walk the same stack
      // twice. This occurs in currently unsupported unhandled FFI callback use
      // cases where we need to jump back to the native unwinder, the code below
      // that does this is probably correct but its untested because we don't
      // properly unwind LuaJIT FFI frames (which is a different kind of JIT).
      // When that's fixed we can uncomment this and be more correct.
      // record->luajitUnwindState.frame = NULL;

      DEBUG_PRINT("lj: unwound past the end of the stack... this shouldn't happen");

      // Let's try to continue anyway, to match the old behavior.

      // We have processed all frames, send final frame which will just have
      // a callee proto/pc and no caller proto/pc.  This is fine, we'll make one
      // up, e.g. "main".
      LJScratchSpace *scr = &record->luajitUnwindScratch;
      if ((err = lj_push_frame(
             &record->state, &record->trace, (u64)scr->prev_proto, (u64)0, scr->prev_pc, 0))) {
        return err;
      }
      if (record->luajitUnwindState.is_jit) {
        unwind_native_frame(info, &record->state, true);

        if ((err = resolve_unwind_mapping(record, next_unwinder)) != ERR_OK) {
          DEBUG_PRINT("lj: failed to walk over jit frame");
          *next_unwinder = PROG_UNWIND_STOP;
          return err;
        }
      }
      DEBUG_PRINT("lj: end lua frame");
      *next_unwinder = PROG_UNWIND_NATIVE;
      return ERR_OK;
    }

    LJTValue frame_val;
    if (bpf_probe_read_user(&frame_val, sizeof(LJTValue), frame)) {
      return ERR_LUAJIT_FRAME_READ;
    }

    // If we have a frame with its own C stack frame we need to exit to native unwinder.
    // In addition, if this is the rootmost C stack, we are done with Lua entirely.
    bool done_with_lua = false;
    if (lj_frame_typep(frame_val) == LJ_FRAME_CP) {
      void *cf = record->luajitUnwindState.cframe;
      if (cf == NULL) {
        cf = record->luajitUnwindState.cframe = record->luajitUnwindScratch.L.cframe;
      }
      if (cf != NULL) {
        void *prev    = lj_cframe_prev(lj_cframe_raw(cf));
        done_with_lua = !prev;

        unwind_native_frame(
          info, &record->state, ((u32)(record->state.text_section_id >> 32)) == LUAJIT_JIT_MARKER);
        if ((err = resolve_unwind_mapping(record, next_unwinder)) != ERR_OK) {
          *next_unwinder = PROG_UNWIND_STOP;
          return err;
        }
        DEBUG_PRINT(
          "lj: walk_lua_stack: cframe encountered, leaving unwinder, %lx prev: %lx",
          (unsigned long)cf,
          (unsigned long)prev);
        record->luajitUnwindState.cframe = prev;
        *next_unwinder                   = PROG_UNWIND_NATIVE;

        exitToNative = true;
      }
    }
    if ((err = lj_record_frame(ctx, record, frame, frame_val, prevframe))) {
      DEBUG_PRINT("lj: walk_lua_stack: lj_record_frame=%d", err);
      return err;
    }
    if ((lj_frame_iscont(frame_val) && lj_frame_iscont_fficb(frame))) {
      // If we have a callback from C into Lua switch to native unwinder.
      // TODO: should we do the same for cpcall frames?
      DEBUG_PRINT("lj: walk_lua_stack: continuation callback frame %lx", (unsigned long)frame_val);
      // We want to record next Lua frame then exit to native.
      exitToNative = true;
    }
    record->luajitUnwindState.prevframe = prevframe = frame;
    if ((err = lj_prev_frame(record, frame_val))) {
      return err;
    }
    if (exitToNative) {
      // Let the native walker kick in now when we called into lua from C.
      *next_unwinder = PROG_UNWIND_NATIVE;
      if (done_with_lua) {
        // We have processed all frames, send final frame which will just have
        // a callee proto/pc and no caller proto/pc.  This is fine, we'll make one
        // up, e.g. "main".
        LJScratchSpace *scr = &record->luajitUnwindScratch;
        if ((err = lj_push_frame(
               &record->state, &record->trace, (u64)scr->prev_proto, (u64)0, scr->prev_pc, 0))) {
          return err;
        }
      }

      return ERR_OK;
    }
  }

  // We exhausted loops, come back for more!
  *next_unwinder = PROG_UNWIND_LUAJIT;

  return ERR_OK;
}

static EBPF_INLINE ErrorCode
find_context(struct pt_regs *ctx, PerCPURecord *record, const LuaJITProcInfo *info)
{
  bool reportG = false;
  void *G_ptr  = NULL;
  void *L_ptr;
  UnwindState *state = &record->state;
  u32 high           = (u32)(state->text_section_id >> 32);

  // The initial state is for the entire anonymous/executable memory range to be mapped to
  // our unwinder with a token file ID. Then we fire a pid event which will call SynchronizeMappings
  // in the HA which will overlay the big anonymous/executable memory range with the actual mappings
  // for each trace with a stack adjustment stored in the low bits.
  if (high == LUAJIT_JIT_MARKER) {
    record->luajitUnwindState.is_jit = true;

    // Once the HA fills in text_section_bias with G we'll stop sending these report_pids.
    if (state->text_section_bias == 0) {
      DEBUG_PRINT("lj: unwinding unmapped JIT frame");
      u64 pid_tgid = (u64)record->trace.pid << 32 | record->trace.tid;
      report_pid(ctx, pid_tgid, RATELIMIT_ACTION_DEFAULT);

      // If top frame isn't luajit we can't rely on the register still holding the DISPATCH table,
      // but once we propagate G to the HA text_section_bias will be set to the G pointer and we can
      // pull cur_L from that. So this is just a bootstrap crutch that just has to work once (or
      // never because G also gets picked up from interpreter hits).
#if defined(__x86_64__)
      G_ptr = (char *)state->r14 - info->g2dispatch;
#elif defined(__aarch64__)
      G_ptr = (char *)state->r22;
#endif
      reportG = true;
    } else {
      G_ptr = (void *)state->text_section_bias;
      DEBUG_PRINT("lj: unwinding trace mapped JIT frame %lx", (unsigned long)G_ptr);
    }
    if (bpf_probe_read_user(&L_ptr, sizeof(void *), (void *)(G_ptr + info->cur_L_offset))) {
      DEBUG_PRINT(
        "lj: failed to read G->cur_L %lx", (unsigned long)((void *)(G_ptr + info->cur_L_offset)));
      increment_metric(metricID_UnwindLuaJITErrNoContext);
      return ERR_LUAJIT_READ_LUA_CONTEXT;
    }
  } else {
    // Interpreter, L is always [rsp+0x10].
    if (bpf_probe_read_user(&L_ptr, sizeof(void *), (void *)(state->sp + LJ_L_STACK_OFFSET))) {
      DEBUG_PRINT("lj: failed to read stack");
      increment_metric(metricID_UnwindLuaJITErrNoContext);
      return ERR_LUAJIT_READ_LUA_CONTEXT;
    }
    reportG = true;
  }

  LJScratchSpace *scr = &record->luajitUnwindScratch;
  if (bpf_probe_read_user(&scr->L, sizeof(LJState), (char *)L_ptr + LJ_L_PART_OFFSET)) {
    DEBUG_PRINT("lj: bad L: failed to read L from: %lx", (unsigned long)L_ptr);
    increment_metric(metricID_UnwindLuaJITErrNoContext);
    return ERR_LUAJIT_READ_LUA_CONTEXT;
  }

  // If we came through interpreter we won't have G yet.
  if (G_ptr == NULL) {
    G_ptr = (void *)scr->L.glref;
  }

  if (bpf_probe_read_user(
        &scr->G, sizeof(LJGlobalPart), (void *)((char *)G_ptr + info->cur_L_offset))) {
    DEBUG_PRINT(
      "lj: bad G picked up from L: failed to read G->cur_L: %lx, %lx",
      (unsigned long)G_ptr,
      (unsigned long)info->cur_L_offset);
    increment_metric(metricID_UnwindLuaJITErrNoContext);
    return ERR_LUAJIT_READ_LUA_CONTEXT;
  }

  if (L_ptr != scr->G.cur_L) {
    DEBUG_PRINT(
      "lj: L context check failed: %lx != %lx", (unsigned long)L_ptr, (unsigned long)scr->G.cur_L);
    increment_metric(metricID_UnwindLuaJITErrLMismatch);
    return ERR_LUAJIT_L_MISMATCH;
  }

  DEBUG_PRINT("lj: L context: %lx", (unsigned long)L_ptr);
  record->luajitUnwindState.L_ptr = L_ptr;

  // If we have valid context let's report it if we haven't mapped its traces yet.
  if (reportG) {
    u64 *data = push_frame(
      &record->state,
      &record->trace,
      FRAME_MARKER_LUAJIT,
      FRAME_FLAG_PID_SPECIFIC,
      LUAJIT_G_REPORT,
      1);
    if (!data)
      return ERR_STACK_LENGTH_EXCEEDED;
    data[0] = (u64)G_ptr;
  }

  // The JIT doesn't update base as it goes but it does update G.jit_base.
  if (high == LUAJIT_JIT_MARKER) {
    record->luajitUnwindState.frame = scr->G.jit_base - 1;
  }
  // otherwise, if the first unwinder was Luajit, then we're in
  // the interpreter. L->base won't have been updated, but
  // we should have base in a register.
  //
  // From vm_x64.dasc:
  // |.define BASE,		rdx
  else if (record->initialUnwinder == PROG_UNWIND_LUAJIT) {
#if defined(__x86_64__)
    record->luajitUnwindState.frame = (LJTValue *)(ctx->dx) - 1;
#elif defined(__aarch64__)
    record->luajitUnwindState.frame = (LJTValue *)(ctx->regs[19]) - 1;
#else
  #error unsupported architecture
#endif
  } else {
    record->luajitUnwindState.frame = scr->L.base - 1;
  }

  return ERR_OK;
}

static EBPF_INLINE int unwind_luajit(struct pt_regs *ctx)
{
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  UnwindState *state   = &record->state;
  int unwinder         = get_next_unwinder_after_interpreter();
  ErrorCode error      = ERR_OK;
  u32 pid              = record->trace.pid;
  LuaJITProcInfo *info = bpf_map_lookup_elem(&luajit_procs, &pid);
  if (!info) {
    DEBUG_PRINT("lj: no LuaJIT introspection data");
    error = ERR_LUAJIT_NO_PROC_INFO;
    increment_metric(metricID_UnwindLuaJITErrNoProcInfo);
    goto exit;
  }
  increment_metric(metricID_UnwindLuaJITAttempts);

  if (record->luajitUnwindState.frame == 0) {
    if ((error = find_context(ctx, record, info))) {
      goto exit;
    }
  }

  if ((error = walk_luajit_stack(ctx, record, info, &unwinder))) {
    goto exit;
  }

exit:
  state->unwind_error = error;
  tail_call(ctx, unwinder);
  return -1;
}
MULTI_USE_FUNC(unwind_luajit)
