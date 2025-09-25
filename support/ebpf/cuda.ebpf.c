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

  u32 cudaId = 0;
  int err;

#if defined(__aarch64__)
  // ARM64: Arguments: 4@[sp, 36]
  u64 sp = ctx->sp;
  err    = bpf_probe_read_user(&cudaId, sizeof(cudaId), (void *)(sp + 36));
#else
  // AMD64: Arguments: 4@-36(%rbp)
  u64 rbp = ctx->bp;
  err     = bpf_probe_read_user(&cudaId, sizeof(cudaId), (void *)rbp - 36);
#endif

  if (err)
    return err;
  DEBUG_PRINT("cuda_correlation_probe: correlationId=%u", cudaId);

  u64 ts = bpf_ktime_get_ns();
  return collect_trace(ctx, TRACE_CUDA_LAUNCH, pid, tid, ts, 0, cudaId);
}

struct kernel_timing {
  u32 pid;
  u32 correlation_id;
  u64 start;
  u64 end;
  u32 deviceId;
  u32 streamId;
  u32 graphId;
  char kernelName[128];
};

bpf_map_def SEC("maps") cuda_timing_events = {
  .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u32),
  .max_entries = 0,
};

// uint64_t start, uint64_t end, uint32_t correlationId, uint32_t deviceId, const char *kernelName
// AMD64 Arguments: 8@%rax 8@%rdx 8@-40(%rbp) 4@%ecx 8@%rsi
// ARM64 Arguments: 8@x1 8@x2 8@[sp, 112] 4@x3 8@x0
static EBPF_INLINE int cuda_kernel_exec(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  u64 start, end;
  u64 correlationId = 0;
  u32 deviceId;
  const char *name;
  int err;

#if defined(__aarch64__)
  // ARM64: 8@x1 8@x2 8@[sp, 112] 4@x3 8@x0
  start  = PT_REGS_PARM2(ctx); // x1
  end    = PT_REGS_PARM3(ctx); // x2
  u64 sp = ctx->sp;
  err    = bpf_probe_read_user(&correlationId, sizeof(correlationId), (void *)(sp + 112));
  if (err) {
    correlationId = 0;
  }
  deviceId = PT_REGS_PARM4(ctx);               // x3
  name     = (const char *)PT_REGS_PARM1(ctx); // x0
#else
  // AMD64: 8@%rax 8@%rdx 8@-40(%rbp) 4@%ecx 8@%rsi
  start   = ctx->ax;
  end     = ctx->dx;
  u64 rbp = ctx->bp;
  err     = bpf_probe_read_user(&correlationId, sizeof(correlationId), (void *)rbp - 40);
  if (err) {
    correlationId = 0;
  }
  deviceId = ctx->cx;
  name     = (const char *)ctx->si;
#endif

  u32 cuda_id     = correlationId & 0xFFFFFFFF;
  u32 devId       = deviceId;
  u32 streamId    = (correlationId >> 32) & 0xFFFFFFFF;
  u64 duration_ns = end - start;

  DEBUG_PRINT(
    "cuda_kernel_exec: correlation_id=%u, duration_ns=%llu, name=%s\n", cuda_id, duration_ns, name);

  // Send the actual timing data from the function parameters
  struct kernel_timing timing = {
    .pid            = pid,
    .correlation_id = cuda_id,
    .start          = start,
    .end            = end,
    .deviceId       = devId,
    .streamId       = streamId,
    .graphId        = 0,
  };

  // copy name into timing.name
  int chars = bpf_probe_read_user_str((char *)&timing.kernelName, sizeof(timing.kernelName), name);
  // empty string is a graph launch so put in a sentinel value
  if (chars <= 0) {
    // error reading string
    timing.kernelName[0] = '\1';
    timing.kernelName[1] = '\2';
    timing.kernelName[2] = '\3';
  }

  bpf_perf_event_output(ctx, &cuda_timing_events, BPF_F_CURRENT_CPU, &timing, sizeof(timing));

  return 0;
}

// uint64_t start, uint64_t end, uint32_t correlationId, uint32_t deviceId, uint32_t graphId
// AMD64 Arguments: 8@%rax 8@%rdx 8@-64(%rbp) 4@%ecx 4@%esi
// ARM64 Arguments: 8@x1 8@x2 8@[sp, 88] 4@x3 4@x0
static EBPF_INLINE int cuda_graph_exec(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  u64 start, end;
  u64 correlationId = 0;
  u32 deviceId, graphId;
  int err;

#if defined(__aarch64__)
  // ARM64: 8@x1 8@x2 8@[sp, 88] 4@x3 4@x0
  start  = PT_REGS_PARM2(ctx); // x1
  end    = PT_REGS_PARM3(ctx); // x2
  u64 sp = ctx->sp;
  err    = bpf_probe_read_user(&correlationId, sizeof(correlationId), (void *)(sp + 88));
  if (err) {
    correlationId = 0;
  }
  deviceId = PT_REGS_PARM4(ctx); // x3
  graphId  = PT_REGS_PARM1(ctx); // x0
#else
  // AMD64: 8@%rax 8@%rdx 8@-64(%rbp) 4@%ecx 4@%esi
  start   = ctx->ax;
  end     = ctx->dx;
  u64 rbp = ctx->bp;
  err     = bpf_probe_read_user(&correlationId, sizeof(correlationId), (void *)rbp - 64);
  if (err) {
    correlationId = 0;
  }
  deviceId = ctx->cx;
  graphId  = ctx->si;
#endif

  u32 cuda_id     = correlationId & 0xFFFFFFFF;
  u32 devId       = deviceId;
  u32 streamId    = (correlationId >> 32) & 0xFFFFFFFF;
  u64 duration_ns = end - start;

  DEBUG_PRINT(
    "cuda_graph_exec: kernel_id=%u, duration_ns=%llu graph_id=%u\n", cuda_id, duration_ns, graphId);

  // Send the actual timing data from the function parameters
  struct kernel_timing timing = {
    .pid            = pid,
    .correlation_id = cuda_id,
    .start          = start,
    .end            = end,
    .deviceId       = devId,
    .streamId       = streamId,
    .graphId        = graphId,
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
