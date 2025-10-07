#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

static EBPF_INLINE int cuda_correlation(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u32 cuda_id = 0;
  int err;

#if defined(__aarch64__)
  // ARM64: Arguments: 4@[sp, 36]
  u64 sp = ctx->sp;
  err    = bpf_probe_read_user(&cuda_id, sizeof(cuda_id), (void *)(sp + 36));
#else
  // AMD64: Arguments: 4@-36(%rbp)
  u64 rbp = ctx->bp;
  err     = bpf_probe_read_user(&cuda_id, sizeof(cuda_id), (void *)rbp - 36);
#endif

  if (err)
    return err;
  DEBUG_PRINT("cuda_correlation_probe: correlation_id=%u", cuda_id);

  u64 ts = bpf_ktime_get_ns();
  return collect_trace(ctx, TRACE_CUDA_LAUNCH, pid, tid, ts, 0, cuda_id);
}

struct kernel_timing {
  u32 pid;
  u32 correlation_id;
  u64 start;
  u64 end;
  u32 device_id;
  u32 stream_id;
  u32 graph_id;
  char kernel_name[128];
};

bpf_map_def SEC("maps") cuda_timing_events = {
  .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u32),
  .max_entries = 0,
};

// uint64_t start, uint64_t end, uint32_t correlation_id, uint32_t device_id, const char *kernelName
// AMD64 Arguments: 8@%rax 8@%rdx 8@-40(%rbp) 4@%ecx 8@%rsi
// ARM64 Arguments: 8@x1 8@x2 8@[sp, 112] 4@x3 8@x0
static EBPF_INLINE int cuda_kernel_exec(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  u64 start, end;
  u64 correlation_id = 0;
  u32 device_id;
  const char *name;
  int err;

#if defined(__aarch64__)
  // ARM64: 8@x1 8@x2 8@[sp, 112] 4@x3 8@x0
  start  = PT_REGS_PARM2(ctx); // x1
  end    = PT_REGS_PARM3(ctx); // x2
  u64 sp = ctx->sp;
  err    = bpf_probe_read_user(&correlation_id, sizeof(correlation_id), (void *)(sp + 112));
  if (err) {
    correlation_id = 0;
  }
  device_id = PT_REGS_PARM4(ctx);               // x3
  name      = (const char *)PT_REGS_PARM1(ctx); // x0
#else
  // AMD64: 8@%rax 8@%rdx 8@-40(%rbp) 4@%ecx 8@%rsi
  start   = ctx->ax;
  end     = ctx->dx;
  u64 rbp = ctx->bp;
  err     = bpf_probe_read_user(&correlation_id, sizeof(correlation_id), (void *)rbp - 40);
  if (err) {
    correlation_id = 0;
  }
  device_id = ctx->cx;
  name      = (const char *)ctx->si;
#endif

  u32 cuda_id     = correlation_id & 0xFFFFFFFF;
  u32 dev_id      = device_id;
  u32 stream_id   = (correlation_id >> 32) & 0xFFFFFFFF;
  u64 duration_ns = end - start;

  DEBUG_PRINT(
    "cuda_kernel_exec: correlation_id=%u, duration_ns=%llu, name=%s\n", cuda_id, duration_ns, name);

  // Send the actual timing data from the function parameters
  struct kernel_timing timing = {
    .pid            = pid,
    .correlation_id = cuda_id,
    .start          = start,
    .end            = end,
    .device_id      = dev_id,
    .stream_id      = stream_id,
    .graph_id       = 0,
  };

  // copy name into timing.name
  int chars =
    bpf_probe_read_user_str((char *)&timing.kernel_name, sizeof(timing.kernel_name), name);
  // empty string is a graph launch so put in a sentinel value
  if (chars <= 0) {
    // error reading string
    timing.kernel_name[0] = 'e';
    timing.kernel_name[1] = 'r';
    timing.kernel_name[2] = 'r';
    timing.kernel_name[3] = '\0';
  }

  bpf_perf_event_output(ctx, &cuda_timing_events, BPF_F_CURRENT_CPU, &timing, sizeof(timing));

  return 0;
}

// uint64_t start, uint64_t end, uint32_t correlation_id, uint32_t device_id, uint32_t graph_id
// AMD64 Arguments: 8@%rax 8@%rdx 8@-64(%rbp) 4@%ecx 4@%esi
// ARM64 Arguments: 8@x1 8@x2 8@[sp, 88] 4@x3 4@x0
static EBPF_INLINE int cuda_graph_exec(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  u64 start, end;
  u64 correlation_id = 0;
  u32 device_id, graph_id;
  int err;

#if defined(__aarch64__)
  // ARM64: 8@x1 8@x2 8@[sp, 88] 4@x3 4@x0
  start  = PT_REGS_PARM2(ctx); // x1
  end    = PT_REGS_PARM3(ctx); // x2
  u64 sp = ctx->sp;
  err    = bpf_probe_read_user(&correlation_id, sizeof(correlation_id), (void *)(sp + 88));
  if (err) {
    correlation_id = 0;
  }
  device_id = PT_REGS_PARM4(ctx); // x3
  graph_id  = PT_REGS_PARM1(ctx); // x0
#else
  // AMD64: 8@%rax 8@%rdx 8@-64(%rbp) 4@%ecx 4@%esi
  start   = ctx->ax;
  end     = ctx->dx;
  u64 rbp = ctx->bp;
  err     = bpf_probe_read_user(&correlation_id, sizeof(correlation_id), (void *)rbp - 64);
  if (err) {
    correlation_id = 0;
  }
  device_id = ctx->cx;
  graph_id  = ctx->si;
#endif

  u32 cuda_id     = correlation_id & 0xFFFFFFFF;
  u32 dev_id      = device_id;
  u32 stream_id   = (correlation_id >> 32) & 0xFFFFFFFF;
  u64 duration_ns = end - start;

  DEBUG_PRINT(
    "cuda_graph_exec: kernel_id=%u, duration_ns=%llu graph_id=%u\n",
    cuda_id,
    duration_ns,
    graph_id);

  // Send the actual timing data from the function parameters
  struct kernel_timing timing = {
    .pid            = pid,
    .correlation_id = cuda_id,
    .start          = start,
    .end            = end,
    .device_id      = dev_id,
    .stream_id      = stream_id,
    .graph_id       = graph_id,
  };

  bpf_perf_event_output(ctx, &cuda_timing_events, BPF_F_CURRENT_CPU, &timing, sizeof(timing));

  return 0;
}

SEC("usdt/cuda_probe")
int cuda_probe(struct pt_regs *ctx)
{
  u64 cookie = bpf_get_attach_cookie(ctx);
  switch (cookie) {
  case 'c': return cuda_correlation(ctx);
  case 'k': return cuda_kernel_exec(ctx);
  case 'g': return cuda_graph_exec(ctx);
  default: DEBUG_PRINT("cuda_probe: unknown cookie %llu", cookie); break;
  }
  return 0;
}

// Individual probe entry points for single-shot mode
SEC("usdt/parcagpu/cuda_correlation")
int usdt_parcagpu_cuda_correlation(struct pt_regs *ctx)
{
  return cuda_correlation(ctx);
}

SEC("usdt/parcagpu/cuda_kernel")
int usdt_parcagpu_cuda_kernel(struct pt_regs *ctx)
{
  return cuda_kernel_exec(ctx);
}

SEC("usdt/parcagpu/cuda_graph")
int usdt_parcagpu_cuda_graph(struct pt_regs *ctx)
{
  return cuda_graph_exec(ctx);
}
