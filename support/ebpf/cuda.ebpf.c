#include "bpfdefs.h"
#include "types.h"
// cupti_bpf.h uses u32/u64 from types.h, so it must be included after it.
#include "cupti_bpf.h"
#include "tracemgmt.h"
#include "usdt_args.h"

// cuda_correlation reads the correlation ID from the USDT probe and records a trace.
SEC("usdt/parcagpu/cuda_correlation")
int BPF_USDT(cuda_correlation, u32 correlation_id, s32 cbid)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  DEBUG_PRINT("cuda_correlation_probe: correlation_id=%u, cbid=%u", correlation_id, cbid);

  u64 ts      = bpf_ktime_get_ns();
  // Cast cbid to s32 first to get sign extension, then to u64
  u64 cuda_id = correlation_id + ((u64)cbid << 32);
  return collect_trace(ctx, TRACE_CUDA_LAUNCH, pid, tid, ts, 0, cuda_id);
}

// Event type discriminator at offset 0 of every event submitted to cupti_events.
// Each event type has its own struct; the Go consumer peeks the first 4 bytes
// and dispatches accordingly.
#define EVENT_TYPE_KERNEL           1
#define EVENT_TYPE_CUBIN_LOADED     2
#define EVENT_TYPE_PC_SAMPLE        3
#define EVENT_TYPE_STALL_REASON_MAP 4
#define EVENT_TYPE_ERROR            5

#define MAX_KERNEL_NAME_LEN   256
#define MAX_FUNC_NAME_LEN     128
#define MAX_ERROR_MSG_LEN     256
#define MAX_ERROR_COMP_LEN    64
#define STALL_REASON_NAME_LEN 64

struct kernel_event {
  u32 event_type; // = EVENT_TYPE_KERNEL
  u32 pid;
  u64 start;
  u64 end;
  u64 graph_node_id;
  u32 correlation_id;
  u32 device_id;
  u32 stream_id;
  u32 graph_id;
  char kernel_name[MAX_KERNEL_NAME_LEN];
};

struct cubin_event {
  u32 event_type; // = EVENT_TYPE_CUBIN_LOADED
  u32 pid;
  u64 cubin_crc;
  u64 cubin_ptr; // user-space address (Go reads bytes via /proc/pid/mem)
  u64 cubin_size;
};

struct pc_sample_event {
  u32 event_type; // = EVENT_TYPE_PC_SAMPLE
  u32 stall_reason_count;
  u64 cubin_crc;
  u64 pc_offset;
  u32 function_index;
  u32 correlation_id; // 0 if pre-CUDA-12.4
  u32 pid;
  u32 _pad;
  char function_name[MAX_FUNC_NAME_LEN];
  struct cupti_stall_reason stall_reasons[MAX_STALL_REASONS];
};

struct stall_reason_map_event {
  u32 event_type; // = EVENT_TYPE_STALL_REASON_MAP
  u32 count;
  u32 pid;
  u32 _pad;
  char names[MAX_STALL_REASONS][STALL_REASON_NAME_LEN];
};

struct error_event {
  u32 event_type; // = EVENT_TYPE_ERROR
  s32 code;
  u32 pid;
  u32 _pad;
  char message[MAX_ERROR_MSG_LEN];
  char component[MAX_ERROR_COMP_LEN];
};

// Per-CPU scratch space for large structs that exceed the BPF 512-byte stack
// limit (cupti_activity_kernel5 = 160 B; stall_reason_map_event ≈ 4 KB).
// Also stashes pre-parsed USDT args for the activity_batch and pc_sample_batch
// tail calls — bpf_get_attach_cookie does not return the correct cookie after
// bpf_tail_call, so we parse args in cuda_probe and pass them via this map.
#define MAX_BATCH_SIZE     128
#define PTR_BATCH          16
// BPF-side limit for pc_sample_batch.  MAX_PC_BATCH_SIZE (512) from cupti_bpf.h
// is the producer-side max; using it directly blows past the BPF verifier's 1M
// instruction cap because each iteration has conditional stall-reason and
// function-name reads.
#define BPF_PC_BATCH_LIMIT 256
struct cuda_scratch {
  struct cupti_activity_kernel5 rec;
  u64 ab_ptrs_base;
  u32 ab_num_activities;
  u64 pc_ptrs_base;
  u32 pc_count;
};

struct cuda_scratch_heap_t {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct cuda_scratch);
  __uint(max_entries, 1);
} cuda_scratch_heap SEC(".maps");

// Unified ringbuf for all CUPTI events sent to user-space. Every event begins
// with a u32 event_type discriminator at offset 0. 1 MB capacity.
struct cupti_events_t {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20);
} cupti_events SEC(".maps");

SEC("usdt/parcagpu/cuda_kernel")
int BPF_USDT(
  cuda_kernel_exec,
  u64 start,
  u64 end,
  u32 correlation_id,
  u32 device_id,
  u32 stream_id,
  u32 graph_id,
  u64 graph_node_id,
  u64 name_ptr)
{
  u64 pid_tgid     = bpf_get_current_pid_tgid();
  u32 pid          = pid_tgid >> 32;
  const char *name = (const char *)name_ptr;

  struct kernel_event *evt = bpf_ringbuf_reserve(&cupti_events, sizeof(*evt), 0);
  if (!evt) {
    return 0;
  }
  evt->event_type     = EVENT_TYPE_KERNEL;
  evt->pid            = pid;
  evt->correlation_id = correlation_id;
  evt->start          = start;
  evt->end            = end;
  evt->graph_node_id  = graph_node_id;
  evt->device_id      = device_id;
  evt->stream_id      = stream_id;
  evt->graph_id       = graph_id;

  int chars = bpf_probe_read_user_str((char *)&evt->kernel_name, sizeof(evt->kernel_name), name);
  if (chars <= 0) {
    evt->kernel_name[0] = 'e';
    evt->kernel_name[1] = 'r';
    evt->kernel_name[2] = 'r';
    evt->kernel_name[3] = '\0';
  }

  DEBUG_PRINT("cuda_kernel_exec: pid=%u corr_id=%u dev=%u", pid, correlation_id, device_id);

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

SEC("usdt/parcagpu/activity_batch")
int BPF_USDT(cuda_activity_batch, u64 ptrs_base, u32 num_activities)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  u32 zero                     = 0;
  struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
  if (!scratch) {
    return 0;
  }
  struct cupti_activity_kernel5 *rec = &scratch->rec;

  DEBUG_PRINT("cuda_activity_batch: pid=%u num=%u", pid, (u32)num_activities);
  DEBUG_PRINT("cuda_activity_batch: ptrs_base=0x%llx", ptrs_base);

  if (num_activities > MAX_BATCH_SIZE) {
    num_activities = MAX_BATCH_SIZE;
  }

  // Stack-local pointer batch — small enough for the BPF stack.
  u64 ptrs[PTR_BATCH] = {};

  // Nested loop: outer iterates over batches of PTR_BATCH pointers,
  // inner processes each pointer in the batch.  This keeps the verifier's
  // jump-sequence count well under BPF_COMPLEXITY_LIMIT_JMP_SEQ (8192).
  for (u32 batch = 0; batch < MAX_BATCH_SIZE / PTR_BATCH; batch++) {
    u32 base = batch * PTR_BATCH;
    if (base >= num_activities) {
      break;
    }

    if (bpf_probe_read_user(ptrs, sizeof(ptrs), (void *)(ptrs_base + base * sizeof(u64))) != 0) {
      break;
    }

    for (u32 j = 0; j < PTR_BATCH; j++) {
      if (base + j >= num_activities) {
        break;
      }

      u64 rec_ptr = ptrs[j];

      // Read the full activity record and filter by kind.
      if (bpf_probe_read_user(rec, sizeof(*rec), (void *)rec_ptr) != 0) {
        continue;
      }
      if (
        rec->kind != CUPTI_ACTIVITY_KIND_KERNEL &&
        rec->kind != CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL) {
        continue;
      }

      struct kernel_event *evt = bpf_ringbuf_reserve(&cupti_events, sizeof(*evt), 0);
      if (!evt) {
        continue;
      }
      evt->event_type     = EVENT_TYPE_KERNEL;
      evt->pid            = pid;
      evt->correlation_id = rec->correlation_id;
      evt->start          = rec->start;
      evt->end            = rec->end;
      evt->graph_node_id  = rec->graph_node_id;
      evt->device_id      = rec->device_id;
      evt->stream_id      = rec->stream_id;
      evt->graph_id       = rec->graph_id;

      const char *name = (const char *)rec->name_ptr;
      int chars =
        bpf_probe_read_user_str((char *)&evt->kernel_name, sizeof(evt->kernel_name), name);
      if (chars <= 0) {
        evt->kernel_name[0] = 'e';
        evt->kernel_name[1] = 'r';
        evt->kernel_name[2] = 'r';
        evt->kernel_name[3] = '\0';
      }

      DEBUG_PRINT(
        "cuda_activity_batch: corr_id=%u kind=%u dev=%u",
        rec->correlation_id,
        rec->kind,
        rec->device_id);

      bpf_ringbuf_submit(evt, 0);
    }
  }

  return 0;
}

// Tail-call entry point for cuda_activity_batch.  Reads pre-parsed USDT args
// from the scratch map (set by cuda_probe before bpf_tail_call) and forwards
// them to the inline body generated by BPF_USDT.
SEC("usdt/cuda_activity_batch_tail")
int cuda_activity_batch_tail(struct pt_regs *ctx)
{
  u32 zero                     = 0;
  struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
  if (!scratch) {
    return 0;
  }
  return ____cuda_activity_batch(ctx, scratch->ab_ptrs_base, scratch->ab_num_activities);
}

// USDT: parcagpu/cubin_loaded(uint64 crc, const char *cubin, uint64 size).
// Emits a single cubin_event so the Go side can pull bytes via /proc/pid/mem.
SEC("usdt/parcagpu/cubin_loaded")
int BPF_USDT(cuda_cubin_loaded, u64 cubin_crc, u64 cubin_ptr, u64 cubin_size)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  struct cubin_event *evt = bpf_ringbuf_reserve(&cupti_events, sizeof(*evt), 0);
  if (!evt) {
    return 0;
  }
  evt->event_type = EVENT_TYPE_CUBIN_LOADED;
  evt->pid        = pid;
  evt->cubin_crc  = cubin_crc;
  evt->cubin_ptr  = cubin_ptr;
  evt->cubin_size = cubin_size;
  bpf_ringbuf_submit(evt, 0);

  DEBUG_PRINT("cuda_cubin_loaded: pid=%u crc=0x%llx size=%llu", pid, cubin_crc, cubin_size);
  return 0;
}

// USDT: parcagpu/stall_reason_map(const char *names, uint32 count).
// Emits a single stall_reason_map_event with all names blob-copied.
// The event is too big for the BPF stack (~4 KB) so we reserve directly into
// the ringbuf and read user memory through that pointer.
SEC("usdt/parcagpu/stall_reason_map")
int BPF_USDT(cuda_stall_reason_map, u64 names_base, u32 count)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  if (count > MAX_STALL_REASONS) {
    count = MAX_STALL_REASONS;
  }

  struct stall_reason_map_event *evt = bpf_ringbuf_reserve(&cupti_events, sizeof(*evt), 0);
  if (!evt) {
    return 0;
  }
  evt->event_type = EVENT_TYPE_STALL_REASON_MAP;
  evt->count      = count;
  evt->pid        = pid;
  evt->_pad       = 0;

  // Single blob copy of the whole names table.  The producer guarantees the
  // upstream buffer is exactly MAX_STALL_REASONS*STALL_REASON_NAME_LEN bytes
  // and zero-padded.
  if (bpf_probe_read_user(evt->names, sizeof(evt->names), (void *)names_base) != 0) {
    bpf_ringbuf_discard(evt, 0);
    return 0;
  }

  bpf_ringbuf_submit(evt, 0);
  DEBUG_PRINT("cuda_stall_reason_map: pid=%u count=%u", pid, count);
  return 0;
}

// USDT: parcagpu/pc_sample_batch(const void **ptrs, uint32 count).
// Iterates pointers to CUpti_PCSamplingPCData records, chases each one and
// emits a pc_sample_event per record.  Heavy loop, tail-called from cuda_probe.
SEC("usdt/parcagpu/pc_sample_batch")
int BPF_USDT(cuda_pc_sample_batch, u64 ptrs_base, u32 count)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  if (count > BPF_PC_BATCH_LIMIT) {
    count = BPF_PC_BATCH_LIMIT;
  }

  // Nested loop mirrors cuda_activity_batch — outer reads PTR_BATCH pointers
  // at a time into a stack-local array, inner processes them.  Keeps the
  // verifier's jump-sequence count under control.
  u64 ptrs[PTR_BATCH] = {};

  for (u32 batch = 0; batch < BPF_PC_BATCH_LIMIT / PTR_BATCH; batch++) {
    u32 base = batch * PTR_BATCH;
    if (base >= count) {
      break;
    }

    if (bpf_probe_read_user(ptrs, sizeof(ptrs), (void *)(ptrs_base + base * sizeof(u64))) != 0) {
      break;
    }

    for (u32 j = 0; j < PTR_BATCH; j++) {
      if (base + j >= count) {
        break;
      }

      u64 rec_ptr = ptrs[j];
      if (rec_ptr == 0) {
        continue;
      }

      struct cupti_pc_data rec = {};
      if (bpf_probe_read_user(&rec, sizeof(rec), (void *)rec_ptr) != 0) {
        continue;
      }

      struct pc_sample_event *evt = bpf_ringbuf_reserve(&cupti_events, sizeof(*evt), 0);
      if (!evt) {
        continue;
      }
      evt->event_type     = EVENT_TYPE_PC_SAMPLE;
      evt->pid            = pid;
      evt->_pad           = 0;
      evt->cubin_crc      = rec.cubin_crc;
      evt->pc_offset      = rec.pc_offset;
      evt->function_index = rec.function_index;
      evt->correlation_id = 0;

      // CUDA 12.4+ / CUPTI v22+ records have correlationId immediately after
      // the base struct (size > 56 indicates the extended layout).
      if (rec.size > CUPTI_PC_DATA_BASE_SIZE) {
        u32 corr = 0;
        bpf_probe_read_user(&corr, sizeof(corr), (void *)(rec_ptr + CUPTI_PC_DATA_BASE_SIZE));
        evt->correlation_id = corr;
      }

      if (rec.function_name_ptr) {
        bpf_probe_read_user_str(
          evt->function_name, sizeof(evt->function_name), (void *)rec.function_name_ptr);
      } else {
        evt->function_name[0] = '\0';
      }

      u32 sr_count = rec.stall_reason_count;
      if (sr_count > MAX_STALL_REASONS) {
        sr_count = MAX_STALL_REASONS;
      }
      evt->stall_reason_count = sr_count;

      if (rec.stall_reason_ptr && sr_count > 0) {
        // Fixed-size copy avoids verifier state explosion from the variable-
        // length sr_count * sizeof(...).  Extra entries beyond sr_count are
        // harmless (consumer reads only sr_count entries).
        bpf_probe_read_user(
          evt->stall_reasons, sizeof(evt->stall_reasons), (void *)rec.stall_reason_ptr);
      }

      bpf_ringbuf_submit(evt, 0);
    }
  }

  return 0;
}

// Tail-call entry point for cuda_pc_sample_batch.  Reads pre-parsed USDT args
// from the scratch map (set by cuda_probe before bpf_tail_call).
SEC("usdt/cuda_pc_sample_batch_tail")
int cuda_pc_sample_batch_tail(struct pt_regs *ctx)
{
  u32 zero                     = 0;
  struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
  if (!scratch) {
    return 0;
  }
  return ____cuda_pc_sample_batch(ctx, scratch->pc_ptrs_base, scratch->pc_count);
}

// USDT: parcagpu/error(int32 code, const char *message, const char *component).
SEC("usdt/parcagpu/error")
int BPF_USDT(cuda_error, s32 code, u64 message_ptr, u64 component_ptr)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;

  struct error_event *evt = bpf_ringbuf_reserve(&cupti_events, sizeof(*evt), 0);
  if (!evt) {
    return 0;
  }
  evt->event_type   = EVENT_TYPE_ERROR;
  evt->code         = code;
  evt->pid          = pid;
  evt->_pad         = 0;
  evt->message[0]   = '\0';
  evt->component[0] = '\0';
  if (message_ptr) {
    bpf_probe_read_user_str(evt->message, sizeof(evt->message), (void *)message_ptr);
  }
  if (component_ptr) {
    bpf_probe_read_user_str(evt->component, sizeof(evt->component), (void *)component_ptr);
  }
  bpf_ringbuf_submit(evt, 0);

  DEBUG_PRINT("cuda_error: pid=%u code=%d", pid, code);
  return 0;
}

// Cookie values for the cuda_probe multi-probe dispatcher.
// Must match the cookie values set in cuda.go.
#define CUDA_PROG_CORRELATION     0
#define CUDA_PROG_KERNEL_EXEC     1
#define CUDA_PROG_ACTIVITY_BATCH  2
#define CUDA_PROG_CUBIN_LOADED    3
#define CUDA_PROG_PC_SAMPLE_BATCH 4
#define CUDA_PROG_STALL_REASON    5
#define CUDA_PROG_ERROR           6

// Tail-call prog array for cuda_probe.  Heavy loop bodies (activity_batch and
// pc_sample_batch) push the inlined dispatcher past BPF_COMPLEXITY_LIMIT_JMP_SEQ
// (8192), so they live in dedicated tail-called programs.  Other handlers are
// inlined directly in cuda_probe.
//
// Key 0: cuda_activity_batch_tail
// Key 1: cuda_pc_sample_batch_tail
struct cuda_progs_t {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 2);
} cuda_progs SEC(".maps");

SEC("usdt/cuda_probe")
int cuda_probe(struct pt_regs *ctx)
{
  u64 full_cookie = bpf_get_attach_cookie(ctx);
  u32 cookie      = (u32)(full_cookie & 0xFFFFFFFF);

  switch (cookie) {
  case CUDA_PROG_CORRELATION: return BPF_USDT_CALL(cuda_correlation, correlation_id, cbid);
  case CUDA_PROG_KERNEL_EXEC:
    return BPF_USDT_CALL(
      cuda_kernel_exec,
      start,
      end,
      correlation_id,
      device_id,
      stream_id,
      graph_id,
      graph_node_id,
      name);
  case CUDA_PROG_ACTIVITY_BATCH: {
    // Parse USDT args before the tail call — bpf_get_attach_cookie does not
    // return the correct cookie after bpf_tail_call.
    u32 zero                     = 0;
    struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
    if (!scratch) {
      break;
    }
    scratch->ab_ptrs_base      = (u64)bpf_usdt_arg0(ctx);
    scratch->ab_num_activities = (u32)bpf_usdt_arg1(ctx);
    bpf_tail_call(ctx, &cuda_progs, 0);
    break;
  }
  case CUDA_PROG_CUBIN_LOADED:
    return BPF_USDT_CALL(cuda_cubin_loaded, cubin_crc, cubin_ptr, cubin_size);
  case CUDA_PROG_PC_SAMPLE_BATCH: {
    u32 zero                     = 0;
    struct cuda_scratch *scratch = bpf_map_lookup_elem(&cuda_scratch_heap, &zero);
    if (!scratch) {
      break;
    }
    scratch->pc_ptrs_base = (u64)bpf_usdt_arg0(ctx);
    scratch->pc_count     = (u32)bpf_usdt_arg1(ctx);
    bpf_tail_call(ctx, &cuda_progs, 1);
    break;
  }
  case CUDA_PROG_STALL_REASON: return BPF_USDT_CALL(cuda_stall_reason_map, names_base, count);
  case CUDA_PROG_ERROR: return BPF_USDT_CALL(cuda_error, code, message_ptr, component_ptr);
  default: DEBUG_PRINT("cuda_probe: unknown cookie %u", cookie); break;
  }
  return 0;
}
