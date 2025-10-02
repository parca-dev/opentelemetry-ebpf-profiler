#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

SEC("usdt/rtld/map_complete")
int usdt_rtld_map_complete(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  DEBUG_PRINT("usdt_rtld_map_complete fired: PID=%u TID=%u", pid, tid);

  // Increment the metric for rtld:map_complete hits
  increment_metric(metricID_RtldMapCompleteHits);

  if (report_pid(ctx, pid_tgid, RATELIMIT_ACTION_DEFAULT)) {
    DEBUG_PRINT("Reported PID %u from usdt_rtld_map_complete", pid);
  }

  return 0;
}
