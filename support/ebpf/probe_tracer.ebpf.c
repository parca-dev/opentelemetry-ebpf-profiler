#include "tracemgmt.h"
#include "types.h"
#include "bpfdefs.h"

static inline __attribute__((__always_inline__)) int unwind_probe(struct pt_regs *ctx)
{
  PerCPURecord *record = get_per_cpu_record();
  if (!record)
    return -1;

  UnwindState *state   = &record->state;
  int offset = state->text_section_bias>>32;
  int desc = state->text_section_bias & 0xFFFFFFFF;
  int err;
  DEBUG_PRINT("probe: stack offset:%d, desc: %d", offset, desc);
  DEBUG_PRINT("sp: %llx, bp:%llx", state->sp, state->fp);
  CustomLabelsArray *out = &record->trace.custom_labels;
  if (offset != 0) {
    void *val_addr;
    if (desc == 0) {
        val_addr = (void *)(state->fp - offset);
    } else {
        val_addr = (void *)(state->fp + offset);
    }
    DEBUG_PRINT("probe: got value address: %lx", (unsigned long)val_addr);

    if (out->len >= MAX_CUSTOM_LABELS) {
        return -1;
    }
    CustomLabel *out_lbl = &out->labels[out->len];
    // Probe's are distinguished by first char being 0
    out_lbl->key[0] = '\0';
    out_lbl->key[1] = '0' + (char)out->len;
    void *str_addr;
    if ((err = bpf_probe_read_user(&str_addr, sizeof(void*), (void *)val_addr))) {
      DEBUG_PRINT("probe: failed to read value from stack: %d", err);
      return -1;
    }
    DEBUG_PRINT("probe: got pointer: %lx", (unsigned long)str_addr);
    if ((err = bpf_probe_read_user(out_lbl->val, CUSTOM_LABEL_MAX_VAL_LEN-1, str_addr))) {
      DEBUG_PRINT("probe: failed to read label value: %d", err);
      return -1;
    }
    out_lbl->val[CUSTOM_LABEL_MAX_VAL_LEN-1] = '\0';
    _push(&record->trace, state->pc, out->len, FRAME_MARKER_PROBE);
    out->len++;
  }

  // reset text_section_id and bias so the native unwinder can unwind the real frame.
  u64 pc             = state->text_section_id;
  PIDPage key   = {};
  key.prefixLen = BIT_WIDTH_PID + BIT_WIDTH_PAGE;
  key.pid       = __constant_cpu_to_be32((u32)record->trace.pid);
  key.page      = __constant_cpu_to_be64(pc);

  // Check if we have the data for this virtual address
  PIDPageMappingInfo *val = bpf_map_lookup_elem(&pid_page_to_mapping_info, &key);
  if (!val) {
    DEBUG_PRINT("Failure to look up interval memory mapping for PC 0x%lx", (unsigned long)pc);
    state->error_metric = metricID_UnwindNativeErrWrongTextSection;
    return ERR_NATIVE_NO_PID_PAGE_MAPPING;
  }

  int unwinder;
  decode_bias_and_unwind_program(val->bias_and_unwind_program, &state->text_section_bias, &unwinder);
  state->text_section_id     = val->file_id;
  state->text_section_offset = state->pc - state->text_section_bias;

  unwinder         = get_next_unwinder_after_interpreter(record);
  tail_call(ctx, unwinder);
  return -1;
}
MULTI_USE_FUNC(unwind_probe)