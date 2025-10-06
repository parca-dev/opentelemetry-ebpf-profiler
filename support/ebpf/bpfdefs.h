#ifndef OPTI_BPFDEFS_H
#define OPTI_BPFDEFS_H

#include "bpf_map.h"
#include "kernel.h"

// with_debug_output is declared in native_stack_trace.ebpf.c
extern u32 with_debug_output;

// UNUSED is a macro that marks a parameter or variable as intentionally unused.
// It prevents compiler warnings about unused variables while keeping them in the code.
#define UNUSED __attribute__((unused))

#if defined(TESTING_COREDUMP)

  // BPF_RODATA_VAR declares a global variable in the .rodata section,
  // ensuring it's not optimized away by the compiler or linker.
  //
  // Arguments:
  //   _type: The data type of the variable (e.g., u32, int, struct my_config).
  //   _name: The name of the global variable.
  //   _value: The initial value for the variable.
  #define BPF_RODATA_VAR(_type, _name, _value) _type _name = _value;

  // tools/coredump uses CGO to build the eBPF code. Provide here the glue to
  // dispatch the BPF API to helpers implemented in ebpfhelpers.go.
  #define SEC(NAME)
  #define EBPF_INLINE

  #define printt(fmt, ...)      bpf_log(fmt, ##__VA_ARGS__)
  #define DEBUG_PRINT(fmt, ...) bpf_log(fmt, ##__VA_ARGS__)

  // Macro for loop unrolling. Expands to nothing for TESTING_COREDUMP.
  #define UNROLL

// BPF helpers. Mostly stubs to dispatch the call to Go code with the context ID.
int bpf_tail_call(void *ctx, bpf_map_def *map, int index);
unsigned long long bpf_ktime_get_ns(void);
int bpf_get_current_comm(void *, int);

static inline long bpf_probe_read_user(void *buf, u32 sz, const void *ptr)
{
  long __bpf_probe_read_user(u64, void *, u32, const void *);
  return __bpf_probe_read_user(__cgo_ctx->id, buf, sz, ptr);
}

static inline long bpf_probe_read_kernel(UNUSED void *buf, UNUSED u32 sz, UNUSED const void *ptr)
{
  return -1;
}

static inline u64 bpf_get_current_pid_tgid(void)
{
  return __cgo_ctx->id;
}

static inline void *bpf_map_lookup_elem(bpf_map_def *map, const void *key)
{
  void *__bpf_map_lookup_elem(u64, bpf_map_def *, const void *);
  return __bpf_map_lookup_elem(__cgo_ctx->id, map, key);
}

static inline int bpf_map_update_elem(
  UNUSED bpf_map_def *map, UNUSED const void *key, UNUSED const void *val, UNUSED u64 flags)
{
  return -1;
}

static inline int bpf_map_delete_elem(UNUSED bpf_map_def *map, UNUSED const void *key)
{
  return -1;
}

static inline int bpf_perf_event_output(
  UNUSED void *ctx,
  UNUSED bpf_map_def *mapdef,
  UNUSED unsigned long long flags,
  UNUSED void *data,
  UNUSED int size)
{

  return 0;
}

static inline int bpf_get_stackid(UNUSED void *ctx, UNUSED bpf_map_def *map, UNUSED u64 flags)
{
  return -1;
}

#else // TESTING_COREDUMP

  // Native eBPF build

  // BPF_RODATA_VAR declares a global variable in the .rodata section,
  // ensuring it's not optimized away by the compiler or linker.
  //
  // Arguments:
  //   _type: The data type of the variable (e.g., u32, int, struct my_config).
  //   _name: The name of the global variable.
  //   _value: The initial value for the variable.
  #define BPF_RODATA_VAR(_type, _name, _value)                                                     \
    _type _name __attribute__((section(".rodata.var"), used)) = _value;

// definitions of bpf helper functions we need, as found in
// https://elixir.bootlin.com/linux/v4.11/source/samples/bpf/bpf_helpers.h

static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *)BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value, u64 flags) = (void *)
  BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) = (void *)BPF_FUNC_map_delete_elem;
static int (*bpf_probe_read)(void *dst, int size, const void *unsafe_ptr) = (void *)
  BPF_FUNC_probe_read;
static unsigned long long (*bpf_ktime_get_ns)(void)         = (void *)BPF_FUNC_ktime_get_ns;
static unsigned long long (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static int (*bpf_get_current_comm)(void *buf, int buf_size) = (void *)BPF_FUNC_get_current_comm;
static void (*bpf_tail_call)(void *ctx, void *map, int index) = (void *)BPF_FUNC_tail_call;
static unsigned long long (*bpf_get_current_task)(void)       = (void *)BPF_FUNC_get_current_task;
static int (*bpf_perf_event_output)(
  void *ctx, void *map, unsigned long long flags, void *data, int size) = (void *)
  BPF_FUNC_perf_event_output;
static int (*bpf_get_stackid)(void *ctx, void *map, u64 flags) = (void *)BPF_FUNC_get_stackid;
static unsigned long long (*bpf_get_prandom_u32)(void)         = (void *)BPF_FUNC_get_prandom_u32;

__attribute__((format(printf, 1, 3))) static int (*bpf_trace_printk)(
  const char *fmt, int fmt_size, ...) = (void *)BPF_FUNC_trace_printk;

static long (*bpf_probe_read_user)(void *dst, int size, const void *unsafe_ptr) = (void *)
  BPF_FUNC_probe_read_user;
static long (*bpf_probe_read_kernel)(void *dst, int size, const void *unsafe_ptr) = (void *)
  BPF_FUNC_probe_read_kernel;

/*
 * bpf_probe_read_user_str
 *
 * 	Copy a NUL terminated string from an unsafe user address
 * 	*unsafe_ptr* to *dst*. The *size* should include the
 * 	terminating NUL byte. In case the string length is smaller than
 * 	*size*, the target is not padded with further NUL bytes. If the
 * 	string length is larger than *size*, just *size*-1 bytes are
 * 	copied and the last byte is set to NUL.
 *
 * 	On success, returns the number of bytes that were written,
 * 	including the terminal NUL. This makes this helper useful in
 * 	tracing programs for reading strings, and more importantly to
 * 	get its length at runtime. See the following snippet:
 *
 * 	::
 *
 * 		SEC("kprobe/sys_open")
 * 		void bpf_sys_open(struct pt_regs *ctx)
 * 		{
 * 		        char buf[PATHLEN]; // PATHLEN is defined to 256
 * 		        int res = bpf_probe_read_user_str(buf, sizeof(buf),
 * 			                                  ctx->di);
 *
 * 			// Consume buf, for example push it to
 * 			// userspace via bpf_perf_event_output(); we
 * 			// can use res (the string length) as event
 * 			// size, after checking its boundaries.
 * 		}
 *
 * 	In comparison, using **bpf_probe_read_user**\ () helper here
 * 	instead to read the string would require to estimate the length
 * 	at compile time, and would often result in copying more memory
 * 	than necessary.
 *
 * 	Another useful use case is when parsing individual process
 * 	arguments or individual environment variables navigating
 * 	*current*\ **->mm->arg_start** and *current*\
 * 	**->mm->env_start**: using this helper and the return value,
 * 	one can quickly iterate at the right offset of the memory area.
 *
 * Returns
 * 	On success, the strictly positive length of the output string,
 * 	including the trailing NUL character. On error, a negative
 * 	value.
 */
static long (*bpf_probe_read_user_str)(void *dst, int size, const void *unsafe_ptr) = (void *)
  BPF_FUNC_probe_read_user_str;

/*
 * bpf_get_attach_cookie
 *
 * 	Get bpf_cookie value provided (optionally) during the program
 * 	attachment. It might be different for each individual
 * 	attachment, even if BPF program itself is the same.
 * 	Expects BPF program context *ctx* as a first argument.
 *
 * 	Supported for the following program types:
 * 		- kprobe/uprobe;
 * 		- tracepoint;
 * 		- perf_event.
 *
 * Returns
 * 	Value specified by user at BPF link creation/attachment time
 * 	or 0, if it was not specified.
 */
static long (*bpf_get_attach_cookie)(void *ctx) = (void *)BPF_FUNC_get_attach_cookie;

  // The sizeof in bpf_trace_printk() must include \0, else no output
  // is generated. The \n is not needed on 5.8+ kernels, but definitely on
  // 5.4 kernels.
  #define printt(fmt, ...)                                                                         \
    ({                                                                                             \
      const char ____fmt[] = fmt "\n";                                                             \
      bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                                   \
    })

  #define DEBUG_PRINT(fmt, ...)                                                                    \
    ({                                                                                             \
      if (__builtin_expect(with_debug_output, 0)) {                                                \
        printt(fmt, ##__VA_ARGS__);                                                                \
      }                                                                                            \
    })

  // Sends `SIGTRAP` to the current task, killing it and capturing a coredump.
  //
  // Only use this in code paths that you expect to be hit by a very specific process that you
  // intend to debug. Placing it into frequently taken code paths might otherwise take down
  // important system processes like sshd or your window manager. For frequently taken cases,
  // prefer using the `DEBUG_CAPTURE_COREDUMP_IF_TGID` macro.
  //
  // This macro requires linking against kernel headers >= 5.6.
  #define DEBUG_CAPTURE_COREDUMP()                                                                 \
    ({                                                                                             \
      if (__builtin_expect(with_debug_output, 0)) {                                                \
        /* We don't define `bpf_send_signal_thread` globally because it requires a      */         \
        /* rather recent kernel (>= 5.6) and otherwise breaks builds of older versions. */         \
        long (*bpf_send_signal_thread)(u32 sig) = (void *)BPF_FUNC_send_signal_thread;             \
        bpf_send_signal_thread(SIGTRAP);                                                           \
      }                                                                                            \
    })

  // Like `DEBUG_CAPTURE_COREDUMP`, but only coredumps if the current task is a member of the
  // given thread group ID ("process").
  #define DEBUG_CAPTURE_COREDUMP_IF_TGID(tgid)                                                     \
    ({                                                                                             \
      if (__builtin_expect(with_debug_output, 0) && bpf_get_current_pid_tgid() >> 32 == (tgid)) {  \
        printt("coredumping process %d", (tgid));                                                  \
        long (*bpf_send_signal_thread)(u32 sig) = (void *)BPF_FUNC_send_signal_thread;             \
        bpf_send_signal_thread(SIGTRAP);                                                           \
      }                                                                                            \
    })

  // Definition of SEC as used by the Linux kernel in tools/lib/bpf/bpf_helpers.h for clang
  // compilations.
  #define SEC(name)                                                                                \
    _Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wignored-attributes\"")      \
      __attribute__((section(name), used)) _Pragma("GCC diagnostic pop")
  #define EBPF_INLINE __attribute__((__always_inline__))

  #if defined(__clang__)
    // Macro for loop unrolling. Expands to the appropriate pragma for clang.
    // Unrolls up to 256 loop iterations.
    #define UNROLL _Pragma("unroll 256")
  #else
    // Macro for loop unrolling. Expands to nothing for gcc.
    #define UNROLL
  #endif

#endif // !TESTING_COREDUMP

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#if defined(__x86_64__)
  #define __PT_PARM1_REG di
  #define __PT_PARM2_REG si
  #define __PT_PARM3_REG dx
  #define __PT_PARM4_REG cx
  #define __PT_PARM5_REG r8
#elif defined(__aarch64__)
  #define __PT_PARM1_REG regs[0]
  #define __PT_PARM2_REG regs[1]
  #define __PT_PARM3_REG regs[2]
  #define __PT_PARM4_REG regs[3]
  #define __PT_PARM5_REG regs[4]
#elif
  #error "Unsupported architecture"
#endif

#define PT_REGS_PARM1(x) ((x)->__PT_PARM1_REG)
#define PT_REGS_PARM2(x) ((x)->__PT_PARM2_REG)
#define PT_REGS_PARM3(x) ((x)->__PT_PARM3_REG)
#define PT_REGS_PARM4(x) ((x)->__PT_PARM4_REG)
#define PT_REGS_PARM5(x) ((x)->__PT_PARM5_REG)

#endif // OPTI_BPFDEFS_H
