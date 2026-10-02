#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// origin_id_probe is declared in generic_probe.ebpf.c
extern u16 origin_id_probe;

// uprobe__generic serves as entry point for uprobe based profiling.
SEC("uprobe/generic")
int uprobe__generic(void *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();

  return collect_trace(ctx, origin_id_probe, pid, tid, 0, ts, 0, 0);
}
