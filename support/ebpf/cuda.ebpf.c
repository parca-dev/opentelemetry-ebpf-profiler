#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

SEC("uprobe/cuda_launch_shim")
int cuda_launch_shim(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u64 cudaId = PT_REGS_PARM1(ctx);

  DEBUG_PRINT("cuda_launch_shim: attached, func is 0x%llx", cudaId);
  u64 ts = bpf_ktime_get_ns();
  return collect_trace(ctx, TRACE_CUDA_LAUNCH, pid, tid, ts, 0, cudaId);
}

struct kernel_timing {
  u32 pid;
  u32 kernel_id;
  u32 duration_bits; // float32 as raw bits
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
  // We're now attaching to launchKernelTiming(id: u32, duration_bits: u32)
  // Parameters: RDI = id (u32), RSI = duration_bits (u32)

  u32 kernel_id     = PT_REGS_PARM1(ctx);
  u32 duration_bits = PT_REGS_PARM2(ctx);
  DEBUG_PRINT("cuda_timing_probe: kernel_id=%u, duration_bits=0x%x\n", kernel_id, duration_bits);

  // Send the actual timing data from the function parameters
  struct kernel_timing timing = {
    .pid           = pid,
    .kernel_id     = kernel_id,
    .duration_bits = duration_bits,
  };

  bpf_perf_event_output(ctx, &cuda_timing_events, BPF_F_CURRENT_CPU, &timing, sizeof(timing));

  return 0;
}