// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"
#include "usdt_args.h"

// Test results map to communicate success/failure to userspace
bpf_map_def SEC("maps") usdt_test_results = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u64),
  .max_entries = 64,
};

// Helper to record test result
static EBPF_INLINE void record_result(UNUSED u32 probe_id, u64 value)
{
  bpf_map_update_elem(&usdt_test_results, &probe_id, &value, BPF_ANY);
}

// ============================================================================
// EBPF_INLINE helper functions containing probe logic
// These are called by both individual SEC probes and the multi-probe dispatcher
// ============================================================================

// Test probe logic: simple_probe with args: s32 x=42, s64 y=1234567890, u64 z=0xDEADBEEF
static EBPF_INLINE int handle_simple_probe(struct pt_regs *ctx)
{
  u32 probe_id = 1;
  long arg0    = 0;
  long arg1    = 0;
  long arg2    = 0;
  bpf_usdt_arg(ctx, 0, &arg0);
  bpf_usdt_arg(ctx, 1, &arg1);
  bpf_usdt_arg(ctx, 2, &arg2);

  int specid = __bpf_usdt_spec_id(ctx); // For debugging
  DEBUG_PRINT("simple_probe called: spec=%d, arg0=%ld arg1=%ld", specid, arg0, arg1);
  DEBUG_PRINT("simple_probe arg2=0x%lx", arg2);

  if (arg0 == 42 && arg1 == 1234567890 && arg2 == 0xDEADBEEF) {
    record_result(probe_id, 1);
  } else {
    record_result(probe_id, 0);
  }
  return 0;
}

SEC("usdt/testprov/simple_probe")
int usdt_simple_probe(struct pt_regs *ctx)
{
  return handle_simple_probe(ctx);
}

// Test probe logic: memory_probe with args: s32 *x, s64 *y
static EBPF_INLINE int handle_memory_probe(struct pt_regs *ctx)
{
  u32 probe_id = 2;
  long ptr0    = 0;
  long ptr1    = 0;
  bpf_usdt_arg(ctx, 0, &ptr0);
  bpf_usdt_arg(ctx, 1, &ptr1);

  DEBUG_PRINT("memory_probe called: ptr0=0x%lx ptr1=0x%lx", ptr0, ptr1);

  s32 val0;
  s64 val1;
  if (
    bpf_probe_read_user(&val0, sizeof(val0), (void *)ptr0) ||
    bpf_probe_read_user(&val1, sizeof(val1), (void *)ptr1)) {
    DEBUG_PRINT("memory_probe: read failed");
    return -1;
  }

  DEBUG_PRINT("memory_probe: val0=%d val1=%lld", val0, val1);

  if (val0 == 42 && val1 == 1234567890) {
    DEBUG_PRINT("memory_probe: SUCCESS");
    record_result(probe_id, 1);
  } else {
    DEBUG_PRINT("memory_probe: FAILED");
    record_result(probe_id, 0);
  }
  return 0;
}

SEC("usdt/testprov/memory_probe")
int usdt_memory_probe(struct pt_regs *ctx)
{
  return handle_memory_probe(ctx);
}

// Test probe logic: const_probe with arg: constant 100
static EBPF_INLINE int handle_const_probe(struct pt_regs *ctx)
{
  u32 probe_id = 3;
  long arg0    = 0;
  bpf_usdt_arg(ctx, 0, &arg0);

  DEBUG_PRINT("const_probe called: arg0=%ld", arg0);

  if (arg0 == 100) {
    DEBUG_PRINT("const_probe: SUCCESS");
    record_result(probe_id, 1);
  } else {
    DEBUG_PRINT("const_probe: FAILED");
    record_result(probe_id, 0);
  }
  return 0;
}

SEC("usdt/testprov/const_probe")
int usdt_const_probe(struct pt_regs *ctx)
{
  return handle_const_probe(ctx);
}

// Test probe logic: mixed_probe with args: s32 x, s64 *y, int c, double *f
static EBPF_INLINE int handle_mixed_probe(struct pt_regs *ctx)
{
  u32 probe_id = 4;
  long arg0    = 0;
  long ptr1    = 0;
  long arg2    = 0;
  bpf_usdt_arg(ctx, 0, &arg0);
  bpf_usdt_arg(ctx, 1, &ptr1);
  bpf_usdt_arg(ctx, 2, &arg2);

  DEBUG_PRINT("mixed_probe called: arg0=%ld ptr1=0x%lx arg2=%ld", arg0, ptr1, arg2);

  s64 val1;
  if (bpf_probe_read_user(&val1, sizeof(val1), (void *)ptr1)) {
    DEBUG_PRINT("mixed_probe: read failed");
    return -1;
  }

  DEBUG_PRINT("mixed_probe: val1=%lld", val1);

  if (arg0 == 42 && val1 == 1234567890 && arg2 == 42) {
    DEBUG_PRINT("mixed_probe: SUCCESS");
    record_result(probe_id, 1);
  } else {
    DEBUG_PRINT("mixed_probe: FAILED");
    record_result(probe_id, 0);
  }
  return 0;
}

SEC("usdt/testprov/mixed_probe")
int usdt_mixed_probe(struct pt_regs *ctx)
{
  return handle_mixed_probe(ctx);
}

// Test probe logic: int32_args with args: s32 a=10, b=20, c=30
static EBPF_INLINE int handle_int32_args(struct pt_regs *ctx)
{
  u32 probe_id = 5;
  long arg0    = 0;
  long arg1    = 0;
  long arg2    = 0;
  bpf_usdt_arg(ctx, 0, &arg0);
  bpf_usdt_arg(ctx, 1, &arg1);
  bpf_usdt_arg(ctx, 2, &arg2);

  DEBUG_PRINT("int32_args called: arg0=%ld arg1=%ld arg2=%ld", arg0, arg1, arg2);

  if (arg0 == 10 && arg1 == 20 && arg2 == 30) {
    DEBUG_PRINT("int32_args: SUCCESS");
    record_result(probe_id, 1);
  } else {
    DEBUG_PRINT("int32_args: FAILED");
    record_result(probe_id, 0);
  }
  return 0;
}

SEC("usdt/testprov/int32_args")
int usdt_int32_args(struct pt_regs *ctx)
{
  return handle_int32_args(ctx);
}

// Test probe logic: int64_args with args: s64 a=100, b=200
static EBPF_INLINE int handle_int64_args(struct pt_regs *ctx)
{
  u32 probe_id = 6;
  long arg0    = 0;
  long arg1    = 0;
  bpf_usdt_arg(ctx, 0, &arg0);
  bpf_usdt_arg(ctx, 1, &arg1);

  DEBUG_PRINT("int64_args called: arg0=%ld arg1=%ld", arg0, arg1);

  if (arg0 == 100 && arg1 == 200) {
    DEBUG_PRINT("int64_args: SUCCESS");
    record_result(probe_id, 1);
  } else {
    DEBUG_PRINT("int64_args: FAILED");
    record_result(probe_id, 0);
  }
  return 0;
}

SEC("usdt/testprov/int64_args")
int usdt_int64_args(struct pt_regs *ctx)
{
  return handle_int64_args(ctx);
}

// Test probe logic: mixed_refs with args: s32 *a, s64 *b, s32 c
static EBPF_INLINE int handle_mixed_refs(struct pt_regs *ctx)
{
  u32 probe_id = 7;
  long ptr0    = 0;
  long ptr1    = 0;
  long arg2    = 0;
  bpf_usdt_arg(ctx, 0, &ptr0);
  bpf_usdt_arg(ctx, 1, &ptr1);
  bpf_usdt_arg(ctx, 2, &arg2);

  DEBUG_PRINT("mixed_refs called: ptr0=0x%lx ptr1=0x%lx arg2=%ld", ptr0, ptr1, arg2);

  s32 val0;
  s64 val1;
  if (
    bpf_probe_read_user(&val0, sizeof(val0), (void *)ptr0) ||
    bpf_probe_read_user(&val1, sizeof(val1), (void *)ptr1)) {
    DEBUG_PRINT("mixed_refs: read failed");
    return -1;
  }

  DEBUG_PRINT("mixed_refs: val0=%d val1=%lld", val0, val1);

  if (val0 == 10 && val1 == 100 && arg2 == 30) {
    DEBUG_PRINT("mixed_refs: SUCCESS");
    record_result(probe_id, 1);
  } else {
    DEBUG_PRINT("mixed_refs: FAILED");
    record_result(probe_id, 0);
  }
  return 0;
}

SEC("usdt/testprov/mixed_refs")
int usdt_mixed_refs(struct pt_regs *ctx)
{
  return handle_mixed_refs(ctx);
}

// Test probe logic: uint8_args with args: uint8_t a=5, b=10
static EBPF_INLINE int handle_uint8_args(struct pt_regs *ctx)
{
  u32 probe_id = 8;
  long arg0    = 0;
  long arg1    = 0;
  bpf_usdt_arg(ctx, 0, &arg0);
  bpf_usdt_arg(ctx, 1, &arg1);

  DEBUG_PRINT("uint8_args called: arg0=%ld arg1=%ld", arg0, arg1);

  if (arg0 == 5 && arg1 == 10) {
    DEBUG_PRINT("uint8_args: SUCCESS");
    record_result(probe_id, 1);
  } else {
    DEBUG_PRINT("uint8_args: FAILED");
    record_result(probe_id, 0);
  }
  return 0;
}

SEC("usdt/testprov/uint8_args")
int usdt_uint8_args(struct pt_regs *ctx)
{
  return handle_uint8_args(ctx);
}

// ============================================================================
// Multi-probe dispatcher
// ============================================================================

// Multi-probe entrypoint that dispatches to individual handlers based on cookie
// Similar to cuda.ebpf.c, uses the low 32 bits of cookie for dispatch
SEC("usdt/usdt_test_multi")
int usdt_test_multi(struct pt_regs *ctx)
{
  // Extract user cookie from low 32 bits (high 32 bits contain spec ID)
  u64 full_cookie = bpf_get_attach_cookie(ctx);
  u32 probe_id    = (u32)(full_cookie & 0xFFFFFFFF);

  DEBUG_PRINT("usdt_test_multi called with probe_id=%u", probe_id);

  // Dispatch to inline helper functions (not SEC entry points)
  switch (probe_id) {
  case 1: return handle_simple_probe(ctx);
  case 2: return handle_memory_probe(ctx);
  case 3: return handle_const_probe(ctx);
  case 4: return handle_mixed_probe(ctx);
  case 5: return handle_int32_args(ctx);
  case 6: return handle_int64_args(ctx);
  case 7: return handle_mixed_refs(ctx);
  case 8: return handle_uint8_args(ctx);
  default: DEBUG_PRINT("usdt_test_multi: unknown probe_id %u", probe_id); return 0;
  }
}
