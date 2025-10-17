#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// cuda_correlation reads the correlation ID the usdt probe:
// u32 correlationId
// u32 callbackId
// char* name
// AMD64: 4@-44(%rbp) 4@-64(%rbp) 8@-40(%rbp)
// ARM64:  4@[sp, 60] 4@[sp, 32] 8@[sp, 64]
static EBPF_INLINE int cuda_correlation(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u32 correlation_id, cbid = 0;
  int err;

#if defined(__aarch64__)
  // ARM64: Arguments: 4@[sp, 36]
  u64 addr = ctx->sp;
  err      = bpf_probe_read_user(&correlation_id, sizeof(correlation_id), (void *)(addr + 60));
  if (err)
    return err;
  err = bpf_probe_read_user(&cbid, sizeof(cbid), (void *)(addr + 32));
  if (err)
    return err;
#else
  // AMD64: Arguments: 4@-36(%rbp)
  u64 rbp = ctx->bp;
  err     = bpf_probe_read_user(&correlation_id, sizeof(correlation_id), (void *)rbp - 44);
  if (err)
    return err;
  err = bpf_probe_read_user(&cbid, sizeof(cbid), (void *)rbp - 64);
  if (err)
    return err;
#endif

  DEBUG_PRINT("cuda_correlation_probe: correlation_id=%u, cbid=%u", correlation_id, cbid);

  u64 ts      = bpf_ktime_get_ns();
  u64 cuda_id = correlation_id + ((u64)cbid << 32);
  return collect_trace(ctx, TRACE_CUDA_LAUNCH, pid, tid, ts, 0, cuda_id);
}

struct kernel_timing {
  u32 pid;
  u32 correlation_id;
  u64 start;
  u64 end;
  u64 graph_node_id;
  u32 device_id;
  u32 stream_id;
  u32 graph_id;
  char kernel_name[256];
};

bpf_map_def SEC("maps") cuda_timing_events = {
  .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u32),
  .max_entries = 0,
};

// u64 start
// u64 end
// u32 correlationId
// u32 deviceId
// u32 streamId
// u32 graphId
// const char *kernelName
// AMD64 Arguments: 8@%rax 8@%rdx 4@%ecx 4@%esi 4@%edi 4@%r8d 8@%r9 8@%r10
// ARM64 Arguments: 8@x1 8@x2 4@x3 4@x4 4@x5 4@x6 8@x0
static EBPF_INLINE int cuda_kernel_exec(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  u64 start, end, graph_node_id = 0;
  u32 correlation_id, device_id, stream_id, graph_id = 0;
  const char *name;

#if defined(__aarch64__)
  start          = ctx->regs[1];               // x1
  end            = ctx->regs[2];               // x2
  correlation_id = ctx->regs[3];               // x3
  device_id      = ctx->regs[4];               // x4
  stream_id      = ctx->regs[5];               // x5
  graph_id       = ctx->regs[6];               // x6
  graph_node_id  = ctx->regs[7];               // x7
  name           = (const char *)ctx->regs[0]; // x0
#else
  start          = ctx->ax;
  end            = ctx->dx;
  correlation_id = ctx->cx;
  device_id      = ctx->si;
  stream_id      = ctx->di;
  graph_id       = ctx->r8;
  graph_node_id  = ctx->r9;
  name           = (const char *)ctx->r10;
#endif

  u64 duration_ns = end - start;

  DEBUG_PRINT(
    "cuda_kernel_exec: correlation_id=%u, duration_ns=%llu, name=%s\n",
    correlation_id,
    duration_ns,
    name);

  // Send the actual timing data from the function parameters
  struct kernel_timing timing = {
    .pid            = pid,
    .correlation_id = correlation_id,
    .start          = start,
    .end            = end,
    .graph_node_id  = graph_node_id,
    .device_id      = device_id,
    .stream_id      = stream_id,
    .graph_id       = graph_id,
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

SEC("usdt/cuda_probe")
int cuda_probe(struct pt_regs *ctx)
{
  u64 cookie = bpf_get_attach_cookie(ctx);
  switch (cookie) {
  case 'c': return cuda_correlation(ctx);
  case 'k': return cuda_kernel_exec(ctx);
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
