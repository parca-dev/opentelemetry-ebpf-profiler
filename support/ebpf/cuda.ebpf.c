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

  u32 cudaId = PT_REGS_PARM1(ctx);

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

// uint64_t start, uint64_t end, uint32_t correlationId, 6uint32_t deviceId, uint32_t streamId,const
// char *kernelName
static EBPF_INLINE int cuda_kernel_exec(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  u32 start               = PT_REGS_PARM1(ctx);
  u64 end                 = PT_REGS_PARM2(ctx);
  u64 devAndCorrelationId = PT_REGS_PARM3(ctx);
  u64 streamId            = PT_REGS_PARM4(ctx);
  const char *name        = (const char *)PT_REGS_PARM5(ctx);
  u32 cuda_id             = devAndCorrelationId & 0xFFFFFFFF;
  u32 devId               = devAndCorrelationId >> 32;
  u64 duration_ns         = end - start;

  DEBUG_PRINT(
    "cuda_kernel_exec: correlation_id=%u, duration_ns=%llu, stream=%s\n",
    cuda_id,
    duration_ns,
    name);

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

// uint64_t start, uint64_t end, uint32_t correlationId, uint32_t deviceId, uint32_t streamId,
// uint32_t graphId)
static EBPF_INLINE int cuda_graph_exec(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  u32 start               = PT_REGS_PARM1(ctx);
  u64 end                 = PT_REGS_PARM2(ctx);
  u64 devAndCorrelationId = PT_REGS_PARM3(ctx);
  u64 streamId            = PT_REGS_PARM4(ctx);
  u32 graphId             = PT_REGS_PARM5(ctx);
  u32 cuda_id             = devAndCorrelationId & 0xFFFFFFFF;
  u32 devId               = devAndCorrelationId >> 32;
  u64 duration_ns         = end - start;

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
