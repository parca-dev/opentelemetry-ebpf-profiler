// Native custom labels (and node.js custom labels via v8 introspection)
// reader code. Extracted from interpreter_dispatcher.ebpf.c so that
// upstream changes to that file have less to conflict with.
//
// Include this header in interpreter_dispatcher.ebpf.c *after* the
// cl_procs map definition. It expects the following identifiers to be
// in scope:
//   - cl_procs                  (BPF map: pid -> NativeCustomLabelsProcInfo)
//   - v8_procs                  (BPF map: pid -> V8ProcInfo, via extmaps.h)
//   - tsd_get_base()            (from tsd.h)
//   - bpf_probe_read_user()     (BPF helper)
//   - bpf_map_lookup_elem()     (BPF helper)
//   - increment_metric()        (from tracemgmt.h)
//   - DEBUG_PRINT()             (from bpfdefs.h)
//   - PerCPURecord, V8ProcInfo, NativeCustomLabelsProcInfo,
//     NativeCustomLabelsSet, NativeCustomLabel, CustomLabel,
//     CustomLabelsArray            (from types.h)
//   - metricID_UnwindNativeCustomLabels*, metricID_UnwindNodeCustomLabels*
//                                (from types.h)
//   - MAX_CUSTOM_LABELS, CUSTOM_LABEL_MAX_KEY_LEN, CUSTOM_LABEL_MAX_VAL_LEN
//                                (from types.h)
//   - MIN(a, b)                  (from bpfdefs.h)

#ifndef OPTI_NATIVE_CUSTOM_LABELS_H
#define OPTI_NATIVE_CUSTOM_LABELS_H

static EBPF_INLINE u64 addr_for_tls_symbol(u64 symbol, bool dtv)
{
  u64 tsd_base;
  if (tsd_get_base((void **)&tsd_base) != 0) {
    increment_metric(metricID_UnwindNativeCustomLabelsErrReadTsdBase);
    DEBUG_PRINT("cl: failed to get TSD base for native custom labels");
    return 0;
  }

  int err;
  u64 addr;
  if (dtv) {
    // ELF Handling For Thread-Local Storage, p.5.
    // The thread register points to a "TCB" (Thread Control Block)
    // whose first element is a pointer to a "DTV"  (Dynamic Thread Vector)...
    u64 dtv_addr;
    if ((err = bpf_probe_read_user(&dtv_addr, sizeof(void *), (void *)(tsd_base)))) {
      increment_metric(metricID_UnwindNativeCustomLabelsErrReadData);
      DEBUG_PRINT("Failed to read TLS DTV addr: %d", err);
      return 0;
    }
    // ... and at offsite 16 in the DTV, there is a pointer to the TLS block.
    if ((err = bpf_probe_read_user(&addr, sizeof(void *), (void *)(dtv_addr + 16)))) {
      increment_metric(metricID_UnwindNativeCustomLabelsErrReadData);
      DEBUG_PRINT("Failed to read main TLS block addr: %d", err);
      return 0;
    }
    addr += symbol;
  } else {
    addr = tsd_base + symbol;
  }
  return addr;
}

static EBPF_INLINE u64 get_v8_cped_address(V8ProcInfo *proc)
{
  int err;

  DEBUG_PRINT("node cl: cped_offset=0x%x", proc->cped_offset);

  u64 isolate_ptr_ptr = addr_for_tls_symbol(proc->isolate_sym, true);
  DEBUG_PRINT("node cl: isolate_addr = 0x%llx", isolate_ptr_ptr);
  if (!isolate_ptr_ptr) {
    return 0;
  }

  u64 isolate_ptr;
  if ((err = bpf_probe_read_user(&isolate_ptr, sizeof(void *), (void *)(isolate_ptr_ptr)))) {
    DEBUG_PRINT("node cl: failed to read node custom labels current set pointer: %d", err);
    return 0;
  }

  u64 cped_addr_ptr = isolate_ptr + proc->cped_offset;
  u64 cped_handle;

  if ((err = bpf_probe_read_user(&cped_handle, sizeof(void *), (void *)(cped_addr_ptr)))) {
    DEBUG_PRINT("node cl: failed to read node custom labels current set pointer: %d", err);
    return 0;
  }

  return cped_handle;
}

static EBPF_INLINE bool
read_labelset_into_trace(PerCPURecord *record, NativeCustomLabelsSet *p_current_set)
{
  int err;

  NativeCustomLabelsSet current_set;
  if ((err = bpf_probe_read_user(&current_set, sizeof(current_set), p_current_set))) {
    increment_metric(metricID_UnwindNativeCustomLabelsErrReadData);
    DEBUG_PRINT("cl: failed to read custom labels data: %d", err);
    return false;
  }

  DEBUG_PRINT("cl: native custom labels count: %lu", current_set.count);

  unsigned ct            = 0;
  CustomLabelsArray *out = &record->trace.custom_labels;

  for (int i = 0; i < MAX_CUSTOM_LABELS; i++) {
    if (i >= current_set.count)
      break;
    NativeCustomLabel *lbl_ptr = current_set.storage + i;
    if ((err = bpf_probe_read_user(
           &record->nativeCustomLabel, sizeof(NativeCustomLabel), (void *)(lbl_ptr)))) {
      increment_metric(metricID_UnwindNativeCustomLabelsErrReadData);
      DEBUG_PRINT("cl: failed to read label storage struct: %d", err);
      return false;
    }
    NativeCustomLabel *lbl = &record->nativeCustomLabel;
    if (!lbl->key.buf)
      continue;
    CustomLabel *out_lbl = &out->labels[ct];
    unsigned klen        = MIN(lbl->key.len, CUSTOM_LABEL_MAX_KEY_LEN);
    if ((err = bpf_probe_read_user(out_lbl->key, klen, (void *)lbl->key.buf))) {
      increment_metric(metricID_UnwindNativeCustomLabelsErrReadKey);
      DEBUG_PRINT("cl: failed to read label key: %d", err);
      goto exit;
    }
    out_lbl->key[klen] = 0;
    unsigned vlen      = MIN(lbl->value.len, CUSTOM_LABEL_MAX_VAL_LEN);
    if ((err = bpf_probe_read_user(out_lbl->val, vlen, (void *)lbl->value.buf))) {
      increment_metric(metricID_UnwindNativeCustomLabelsErrReadValue);
      DEBUG_PRINT("cl: failed to read label value: %d", err);
      goto exit;
    }
    out_lbl->val[vlen] = 0;
    ++ct;
  }
exit:
  out->len = ct;
  increment_metric(metricID_UnwindNativeCustomLabelsReadSuccesses);
  return true;
}

static EBPF_INLINE bool
get_native_custom_labels(PerCPURecord *record, NativeCustomLabelsProcInfo *proc)
{
  int err;
  bool is_aarch64 =
#if defined(__aarch64__)
    true
#else
    false
#endif
    ;
  u64 addr = addr_for_tls_symbol(proc->current_set_tls_offset, is_aarch64);
  if (!addr)
    return false;

  DEBUG_PRINT("cl: native custom labels data at 0x%llx", addr);

  NativeCustomLabelsSet *p_current_set;
  if ((err = bpf_probe_read_user(&p_current_set, sizeof(void *), (void *)(addr)))) {
    increment_metric(metricID_UnwindNativeCustomLabelsErrReadData);
    DEBUG_PRINT("Failed to read custom labels current set pointer: %d", err);
    return false;
  }

  if (!p_current_set) {
    DEBUG_PRINT("Null labelset");
    record->trace.custom_labels.len = 0;
    return true;
  }

  return read_labelset_into_trace(record, p_current_set);
}

static EBPF_INLINE void maybe_add_native_custom_labels(PerCPURecord *record)
{
  u32 pid                          = record->trace.pid;
  NativeCustomLabelsProcInfo *proc = bpf_map_lookup_elem(&cl_procs, &pid);
  if (!proc) {
    DEBUG_PRINT("cl: %d does not support native custom labels", pid);
    return;
  }
  DEBUG_PRINT("cl: trace is within a process with native custom labels enabled");
  bool success = get_native_custom_labels(record, proc);
  if (success)
    increment_metric(metricID_UnwindNativeCustomLabelsAddSuccesses);
  else
    increment_metric(metricID_UnwindNativeCustomLabelsAddErrors);
}

bool EBPF_INLINE is_smi(u64 x)
{
  return !(x & 0xFFFFFFFF);
}

#define MAX_V8_HM_TRIES 16
// V8 internals basics:
//
// Note: the information here is valid only for v8
// as embedded in Node on 64-bit machines. Other embedders turn on different
// sets of flags that cause data to be represented differently.
//
// v8 objects are represented by the "Address" type, which is either
// a tagged pointer to a heap object (tagged by setting the LSB to 1)
// or a SMI (short for "small integer") -- a 32-bit signed integer stored in the most significant
// half of a 64-bit value, with the least significant bits set to zero.
//
// So to read a SMI, we do addr >> 32, and to read an object, we do addr - 1.
//
// Since objects can be moved by the GC, they are not usually referenced directly with pointers, but
// rather by "handles" that introduce another layer of indirection: that is,
// a handle usually holds an Address *, rather than an Address.
//
// There are various types of handle: Local, Persistent, Global, but the
// distinction between these does not really matter for our purposes.
//
// Custom labels are based on Node's async context frame feature,
// which is available starting in v22 (requiring to launch Node with a custom flag),
// and on by default starting in v24. When this feature is on,
// all AsyncLocalStorage instances
// (https://nodejs.org/api/async_context.html#class-asynclocalstorage) are stored in v8's
// ContinuationPreservedEmbedderData (CPED) and in most cases propagation is handled by v8 itself.
//
// When this feature is enabled,
// Node installs in the CPED a map (that is, the JavaScript Map type)
// from the AsyncLocalStorage's identity hash to the
// AsyncLocalStorage itself.
//
// JavaScript maps in v8 have the following structure:
// JS Map object -> Handle to "table" (at 0x18)
//
// The handle points to an instance of the C++ OrderedHashMap class,
// which has a 0x10 byte header in base classes,
// followed by an instance of the class's own data,
// whose layout is as follows:
//
// 0x0: element count
// 0x8: deleted element count
// 0x10: bucket count -- 8-byte SMI
// 0x18 ... (one for each bucket): bucket entry indices -- each is an 8-byte SMI.
// Data table (immediately following the bucket indices):
//   Each entry is 0x18 bytes: key, value, next-index.
//   key/value are tagged object handles; next-index is the next index
//   to try if the key doesn't match (also an 8-byte SMI).
//
// So the lookup procedure is as follows:
// 1. Get the hash (as returned by Object::GetIdentityHash)
// 2. Get the bucket index (hash % n_buckets) -- note,
//    this doesn't require an actual mod, because n_buckets is always a
//    power of 2.
// 3. Get the entry index for the bucket (in the data immediately following
//    the bucket count).
// 4. Get the entry. If its key is the same object as what we are looking for
//    (by object identity), we are done. Otherwise, read the next-entry.
//    If it is -1, we have failed, otherwise iterate.
//
// So, our native Node extension does the following:
//
// 1. On first use, create an AsyncLocalStorage, which we will use for
//    storing labelsets. Store both the hash of this ALS and a handle to it
//    at well-known symbols. (The handle is one of the indirect handles described
//    above, so it will be updated by the GC to contain the correct object address
//    even if it moves).
// 2. When withLabels is called, create a new labelset with the required labels and
//    forward it to the ALS's `run` method.
//
// Actually, it's slightly more complicated: we can't just store a labelset directly;
// we need to store something that fits in v8's object hierarchy and which can be
// tracked/finalized by the GC. v8 provides the `ObjectWrap` class for exactly this purpose, so
// we have a C++ type `ClWrap` which inherits from `ObjectWrap` and itself stores a labelset.
// `ClWrap` also stores a fixed u64 token, currently 0xEC9EB507FB5D7903. This
// lets us identify that an object at runtime is actually of that type (as opposed to,
// for example, "undefined").
//
// REFERENCES:
// SMI representation:
//   https://github.com/nodejs/node/blob/09dc7a5985e/deps/v8/include/v8-internal.h#L156-L160
//   https://github.com/nodejs/node/blob/09dc7a5985e/deps/v8/include/v8-internal.h#L85-L88
// Object address representation:
//   https://github.com/nodejs/node/blob/09dc7a5985e/deps/v8/src/objects/tagged.h#L517-L517
//   https://github.com/nodejs/node/blob/09dc7a5985e/deps/v8/include/v8-internal.h#L72-L72
// Handle representation:
//   https://github.com/nodejs/node/blob/09dc7a5985e/deps/v8/include/v8-handle-base.h#L103-L104
//
// JS map representation:
//   https://github.com/nodejs/node/blob/09dc7a5985e/deps/v8/src/objects/js-collection.h#L56-L67
//   https://github.com/nodejs/node/blob/09dc7a5985e/out/Release/obj/gen/torque-generated/src/objects/js-collection-tq.inc#L112-L113
//   https://github.com/nodejs/node/blob/09dc7a5985e/deps/v8/src/objects/js-collection.h#L22-L23
//   https://github.com/nodejs/node/blob/09dc7a5985e/out/Release/obj/gen/torque-generated/src/objects/js-collection-tq.inc#L13-L13
//   https://github.com/nodejs/node/blob/09dc7a5985e/deps/v8/src/objects/js-objects.h#L372-L372
//   https://github.com/nodejs/node/blob/09dc7a5985e/out/Release/obj/gen/torque-generated/src/objects/js-objects-tq.inc#L77-L77
//   https://github.com/nodejs/node/blob/09dc7a5985e/deps/v8/src/objects/js-objects.h#L46-L46
//   https://github.com/nodejs/node/blob/09dc7a5985e/out/Release/obj/gen/torque-generated/src/objects/js-objects-tq.inc#L22-L22
//   (Yes, you really have to trace this whole class hierarchy to prove that
//    kTableOffset, where we store the address of OrderedHashMap, is 0x18)
//
// OrderedHashMap representation:
//   https://github.com/nodejs/node/blob/09dc7a5985e/deps/v8/src/objects/ordered-hash-table.h#L321-L323
//   (You will have to trace through lots of base classes to verify that
//    objects() indeed points to the memory at 0x10.
//    For information on the data layout after that point,
//    see OrderedHashTable.)
static EBPF_INLINE bool maybe_add_node_custom_labels(PerCPURecord *record)
{
  u32 pid                          = record->trace.pid;
  V8ProcInfo *v8_proc              = bpf_map_lookup_elem(&v8_procs, &pid);
  NativeCustomLabelsProcInfo *proc = bpf_map_lookup_elem(&cl_procs, &pid);
  if (!v8_proc || !proc || !proc->has_als_data) {
    DEBUG_PRINT("node cl: pid %d does not support node custom labels", pid);
    return true;
  }
  increment_metric(metricID_UnwindNodeCustomLabelsAttempts);

  int err;
  u64 cped_addr = get_v8_cped_address(v8_proc);

  if (!cped_addr) {
    DEBUG_PRINT("node cl: failed to get v8 CPED address");
    return false;
  }

  DEBUG_PRINT("node cl: CPED address is 0x%llx", cped_addr);
  u64 cped_table_ptr = cped_addr + 0x17; // -1 to untag, then the table is at offset 0x18
  u64 cped_table_addr;
  if ((err = bpf_probe_read_user(&cped_table_addr, sizeof(void *), (void *)(cped_table_ptr)))) {
    DEBUG_PRINT("node cl: failed to read cped table addr: %d", err);
    return false;
  }

  u64 n_buckets_ptr    = cped_table_addr - 1 + 0x10 + 2 * 8;
  u64 first_bucket_ptr = n_buckets_ptr + 8;

  u64 n_buckets_smi;

  if ((err = bpf_probe_read_user(&n_buckets_smi, sizeof(void *), (void *)(n_buckets_ptr)))) {
    DEBUG_PRINT("node cl: failed to read n buckets: %d", err);
    return false;
  }
  if (!is_smi(n_buckets_smi)) {
    DEBUG_PRINT("node cl: N buckets is not a smi: 0x%llx", n_buckets_smi);
    return false;
  }
  s32 n_buckets = n_buckets_smi >> 32;
  DEBUG_PRINT("node cl: N buckets: %d", n_buckets);

  if (n_buckets & (n_buckets - 1)) {
    DEBUG_PRINT("node cl: N buckets is not a power of two: %d", n_buckets);
    return false;
  }

  DEBUG_PRINT(
    "node cl: id hash off: 0x%llx, handle offset: 0x%llx",
    proc->als_identity_hash_tls_offset,
    proc->als_handle_tls_offset);

  u64 als_id_hash_ptr = addr_for_tls_symbol(proc->als_identity_hash_tls_offset, false);
  u64 als_handle_ptr  = addr_for_tls_symbol(proc->als_handle_tls_offset, false);

  int als_id_hash;

  if ((err = bpf_probe_read_user(&als_id_hash, sizeof(int), (void *)als_id_hash_ptr))) {
    DEBUG_PRINT("node cl: failed to read hash: %d", err);
    return false;
  }

  u64 als_handle;
  if ((err = bpf_probe_read_user(&als_handle, sizeof(void *), (void *)als_handle_ptr))) {
    DEBUG_PRINT("node cl: failed to read als handle pointer: %d\n", err);
    return false;
  }

  u64 als_identity;
  if ((err = bpf_probe_read_user(&als_identity, sizeof(void *), (void *)als_handle))) {
    DEBUG_PRINT("node cl: failed to read als identity: %d\n", err);
    return false;
  }

  DEBUG_PRINT("node cl: als identity: 0x%llx; hash: 0x%x", als_identity, als_id_hash);

  int bucket = als_id_hash & (n_buckets - 1);

  u64 entry_idx_ptr = first_bucket_ptr + 8 * bucket;

  int tries;

  u64 value;
  for (tries = 0; tries < MAX_V8_HM_TRIES; ++tries) {
    u64 entry_idx_smi;
    if ((err = bpf_probe_read_user(&entry_idx_smi, sizeof(void *), (void *)entry_idx_ptr))) {
      DEBUG_PRINT("node cl: failed to read next entry index: %d\n", err);
      return false;
    }
    if (!is_smi(entry_idx_smi)) {
      DEBUG_PRINT("node cl: entry index is not a smi: 0x%llx", entry_idx_smi);
      return false;
    }
    s32 entry_idx = entry_idx_smi >> 32;

    if (entry_idx < 0) {
      DEBUG_PRINT("node cl: ALS not found in map.");
      return false;
    }

    DEBUG_PRINT("node cl: entry idx: %d\n", entry_idx);

    struct Entry {
      u64 key;
      u64 value;
      u64 next_index;
    };

    struct Entry e;
    struct Entry *entry_ptr =
      (struct Entry *)(first_bucket_ptr + 8 * n_buckets + sizeof(struct Entry) * entry_idx);
    if ((err = bpf_probe_read_user(&e, sizeof(e), (void *)entry_ptr))) {
      DEBUG_PRINT("node cl: failed to read entry: %d\n", err);
      return false;
    }

    DEBUG_PRINT(
      "node cl: successfully read entry: key: 0x%llx, val: 0x%llx, next: 0x%llx",
      e.key,
      e.value,
      e.next_index);

    if (e.key == als_identity) {
      DEBUG_PRINT("node cl: key matches.");
      value = e.value;
      break;
    }
    DEBUG_PRINT("node cl: key doesn't match; continuing");
    entry_idx_ptr = (u64)(&entry_ptr->next_index);
  }

  if (tries < MAX_V8_HM_TRIES) {
    u64 cl_wrap_ptr_ptr = value - 1 + v8_proc->wrapped_object_offset;
    u64 cl_wrap_ptr;

    if ((err = bpf_probe_read_user(&cl_wrap_ptr, sizeof(u64), (void *)cl_wrap_ptr_ptr))) {
      DEBUG_PRINT("node cl: failed to find ClWrap: %d\n", err);
      return false;
    }

    DEBUG_PRINT("node cl: ClWrap at 0x%llx", cl_wrap_ptr);

    u64 cl_ptr_ptr = cl_wrap_ptr + 24;
    u64 token_ptr  = cl_ptr_ptr + 8;
    u64 token;
    if ((err = bpf_probe_read_user(&token, sizeof(u64), (void *)token_ptr))) {
      DEBUG_PRINT("node cl: failed reading token: %d\n", err);
      return false;
    }
    if (token != 0xEC9EB507FB5D7903) {
      DEBUG_PRINT("node cl: not a labelset");
      return true; // this isn't a failure!
    }
    u64 cl_ptr;
    if ((err = bpf_probe_read_user(&cl_ptr, sizeof(u64), (void *)cl_ptr_ptr))) {
      DEBUG_PRINT("node cl: failed reading cl ptr: %d\n", err);
      return false;
    }

    bool success = read_labelset_into_trace(record, (NativeCustomLabelsSet *)cl_ptr);

    if (success) {
      DEBUG_PRINT("node cl: succeeded reading ls into trace");
      increment_metric(metricID_UnwindNodeCustomLabelsSuccesses);
      return true;
    } else {
      DEBUG_PRINT("node cl: failed to read labelset into trace");
      return false;
    }
  } else {
    DEBUG_PRINT("node cl: couldn't find ls after searching max buckets");
    return false;
  }
}

#endif // OPTI_NATIVE_CUSTOM_LABELS_H
