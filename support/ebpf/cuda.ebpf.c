#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

SEC("uprobe/cuda_launch_probe")
int cuda_launch_probe(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u64 cudaId = PT_REGS_PARM1(ctx);

  DEBUG_PRINT("cuda_launch_probe: attached to parcagpuLaunchKernel/parcagpuGraphLaunch, correlationId=%u", cudaId);
  u64 ts = bpf_ktime_get_ns();
  return collect_trace(ctx, TRACE_CUDA_LAUNCH, pid, tid, ts, 0, cudaId);
}

struct kernel_timing {
  u32 pid;
  u32 kernel_id;
  u64 duration_ns; // Duration in nanoseconds
};

bpf_map_def SEC("maps") cuda_timing_events = {
  .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u32),
  .max_entries = 0,
};

SEC("uprobe/cuda_timing_probe")
int cuda_timing_probe(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  // We're now attaching to parcagpuKernelExecuted(correlationId: u32, duration_ns: u64)
  // Parameters: RDI = correlationId (u32), RSI = duration_ns (u64)

  u32 kernel_id     = PT_REGS_PARM1(ctx);
  u64 duration_ns   = PT_REGS_PARM2(ctx);
  DEBUG_PRINT("cuda_timing_probe: kernel_id=%u, duration_ns=%llu\n", kernel_id, duration_ns);

  // Send the actual timing data from the function parameters
  struct kernel_timing timing = {
    .pid           = pid,
    .kernel_id     = kernel_id,
    .duration_ns   = duration_ns,
  };

  bpf_perf_event_output(ctx, &cuda_timing_events, BPF_F_CURRENT_CPU, &timing, sizeof(timing));

  return 0;
}