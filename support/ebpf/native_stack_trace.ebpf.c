#include "bpfdefs.h"
#include "frametypes.h"
#include "stackdeltatypes.h"
#include "tracemgmt.h"
#include "types.h"

// with_debug_output is set during load time.
BPF_RODATA_VAR(u32, with_debug_output, 0)

// Macro to create a map named exe_id_to_X_stack_deltas that is a nested maps with a fileID for the
// outer map and an array as inner map that holds up to 2^X stack delta entries for the given
// fileID.
#define STACK_DELTA_BUCKET(X)                                                                      \
  bpf_map_def SEC("maps") exe_id_to_##X##_stack_deltas = {                                         \
    .type        = BPF_MAP_TYPE_HASH_OF_MAPS,                                                      \
    .key_size    = sizeof(u64),                                                                    \
    .value_size  = sizeof(u32),                                                                    \
    .max_entries = 4096,                                                                           \
  };

// Create buckets to hold the stack delta information for the executables.
STACK_DELTA_BUCKET(8);
STACK_DELTA_BUCKET(9);
STACK_DELTA_BUCKET(10);
STACK_DELTA_BUCKET(11);
STACK_DELTA_BUCKET(12);
STACK_DELTA_BUCKET(13);
STACK_DELTA_BUCKET(14);
STACK_DELTA_BUCKET(15);
STACK_DELTA_BUCKET(16);
STACK_DELTA_BUCKET(17);
STACK_DELTA_BUCKET(18);
STACK_DELTA_BUCKET(19);
STACK_DELTA_BUCKET(20);
STACK_DELTA_BUCKET(21);
STACK_DELTA_BUCKET(22);
STACK_DELTA_BUCKET(23);

// An array of unwind info contains the all the different UnwindInfo instances
// needed system wide. Individual stack delta entries refer to this array.
bpf_map_def SEC("maps") unwind_info_array = {
  .type        = BPF_MAP_TYPE_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(UnwindInfo),
  // Maximum number of unique stack deltas needed on a system. This is based on
  // normal desktop /usr/bin/* and /usr/lib/*.so having about 9700 unique deltas.
  // Can be increased up to 2^15, see also STACK_DELTA_COMMAND_FLAG.
  .max_entries = 16384,
};

// The decision whether to unwind native stacks or interpreter stacks is made by checking if a given
// PC address falls into the "interpreter loop" of an interpreter. This map helps identify such
// loops: The keys are those executable section IDs that contain interpreter loops, the values
// identify the offset range within this executable section that contains the interpreter loop.
bpf_map_def SEC("maps") interpreter_offsets = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u64),
  .value_size  = sizeof(OffsetRange),
  .max_entries = 32,
};

// Maps fileID and page to information of stack deltas associated with that page.
bpf_map_def SEC("maps") stack_delta_page_to_info = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(StackDeltaPageKey),
  .value_size  = sizeof(StackDeltaPageInfo),
  .max_entries = 40000,
};

// This contains the kernel PCs as returned by bpf_get_stackid(). Unfortunately the ebpf
// program cannot read the contents, so we return the stackid in the Trace directly, and
// make the profiling agent read the kernel mode stack trace portion from this map.
bpf_map_def SEC("maps") kernel_stackmap = {
  .type        = BPF_MAP_TYPE_STACK_TRACE,
  .key_size    = sizeof(u32),
  .value_size  = PERF_MAX_STACK_DEPTH * sizeof(u64),
  .max_entries = 16 * 1024,
};

#include "native_stack_trace.h"

SEC("perf_event/native_tracer_entry")
int native_tracer_entry(struct bpf_perf_event_data *ctx)
{
  // Get the PID and TGID register.
  u64 id  = bpf_get_current_pid_tgid();
  u32 pid = id >> 32;
  u32 tid = id & 0xFFFFFFFF;

  if (pid == 0) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();
  return collect_trace((struct pt_regs *)&ctx->regs, TRACE_SAMPLING, pid, tid, ts, 0, 0);
}
MULTI_USE_FUNC(unwind_native)
