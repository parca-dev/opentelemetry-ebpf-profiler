#include "bpfdefs.h"
#include "tracemgmt.h"

#include "types.h"
#include "usdt.h"

#ifndef BPF_USDT_MAX_SPEC_CNT
  #define BPF_USDT_MAX_SPEC_CNT 256
#endif

#ifndef BPF_USDT_MAX_IP_CNT
  #define BPF_USDT_MAX_IP_CNT (4 * BPF_USDT_MAX_SPEC_CNT)
#endif

// USDT specification maps (libbpf-compatible)
bpf_map_def SEC("maps") __bpf_usdt_specs = {
  .type        = BPF_MAP_TYPE_ARRAY,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(struct bpf_usdt_spec),
  .max_entries = BPF_USDT_MAX_SPEC_CNT,
};

bpf_map_def SEC("maps") __bpf_usdt_ip_to_spec_id = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u64),
  .value_size  = sizeof(u32),
  .max_entries = BPF_USDT_MAX_IP_CNT,
};

// Helper to get pointer to register value in pt_regs based on register ID
static EBPF_INLINE unsigned long *__bpf_usdt_get_reg_ptr(struct pt_regs *ctx, u8 reg_id)
{
#if defined(__x86_64__)
  switch (reg_id) {
  case BPF_USDT_REG_RAX: return &ctx->ax;
  case BPF_USDT_REG_RBX: return &ctx->bx;
  case BPF_USDT_REG_RCX: return &ctx->cx;
  case BPF_USDT_REG_RDX: return &ctx->dx;
  case BPF_USDT_REG_RSI: return &ctx->si;
  case BPF_USDT_REG_RDI: return &ctx->di;
  case BPF_USDT_REG_RBP: return &ctx->bp;
  case BPF_USDT_REG_RSP: return &ctx->sp;
  case BPF_USDT_REG_R8: return &ctx->r8;
  case BPF_USDT_REG_R9: return &ctx->r9;
  case BPF_USDT_REG_R10: return &ctx->r10;
  case BPF_USDT_REG_R11: return &ctx->r11;
  case BPF_USDT_REG_R12: return &ctx->r12;
  case BPF_USDT_REG_R13: return &ctx->r13;
  case BPF_USDT_REG_R14: return &ctx->r14;
  case BPF_USDT_REG_R15: return &ctx->r15;
  case BPF_USDT_REG_RIP: return &ctx->reg_pc;
  default: return NULL;
  }
#elif defined(__aarch64__)
  switch (reg_id) {
  case BPF_USDT_REG_X0: return (unsigned long *)&ctx->regs[0];
  case BPF_USDT_REG_X1: return (unsigned long *)&ctx->regs[1];
  case BPF_USDT_REG_X2: return (unsigned long *)&ctx->regs[2];
  case BPF_USDT_REG_X3: return (unsigned long *)&ctx->regs[3];
  case BPF_USDT_REG_X4: return (unsigned long *)&ctx->regs[4];
  case BPF_USDT_REG_X5: return (unsigned long *)&ctx->regs[5];
  case BPF_USDT_REG_X6: return (unsigned long *)&ctx->regs[6];
  case BPF_USDT_REG_X7: return (unsigned long *)&ctx->regs[7];
  case BPF_USDT_REG_X8: return (unsigned long *)&ctx->regs[8];
  case BPF_USDT_REG_X9: return (unsigned long *)&ctx->regs[9];
  case BPF_USDT_REG_X10: return (unsigned long *)&ctx->regs[10];
  case BPF_USDT_REG_X11: return (unsigned long *)&ctx->regs[11];
  case BPF_USDT_REG_X12: return (unsigned long *)&ctx->regs[12];
  case BPF_USDT_REG_X13: return (unsigned long *)&ctx->regs[13];
  case BPF_USDT_REG_X14: return (unsigned long *)&ctx->regs[14];
  case BPF_USDT_REG_X15: return (unsigned long *)&ctx->regs[15];
  case BPF_USDT_REG_X16: return (unsigned long *)&ctx->regs[16];
  case BPF_USDT_REG_X17: return (unsigned long *)&ctx->regs[17];
  case BPF_USDT_REG_X18: return (unsigned long *)&ctx->regs[18];
  case BPF_USDT_REG_X19: return (unsigned long *)&ctx->regs[19];
  case BPF_USDT_REG_X20: return (unsigned long *)&ctx->regs[20];
  case BPF_USDT_REG_X21: return (unsigned long *)&ctx->regs[21];
  case BPF_USDT_REG_X22: return (unsigned long *)&ctx->regs[22];
  case BPF_USDT_REG_X23: return (unsigned long *)&ctx->regs[23];
  case BPF_USDT_REG_X24: return (unsigned long *)&ctx->regs[24];
  case BPF_USDT_REG_X25: return (unsigned long *)&ctx->regs[25];
  case BPF_USDT_REG_X26: return (unsigned long *)&ctx->regs[26];
  case BPF_USDT_REG_X27: return (unsigned long *)&ctx->regs[27];
  case BPF_USDT_REG_X28: return (unsigned long *)&ctx->regs[28];
  case BPF_USDT_REG_X29: return (unsigned long *)&ctx->regs[29]; // FP
  case BPF_USDT_REG_X30: return (unsigned long *)&ctx->regs[30]; // LR
  case BPF_USDT_REG_SP: return (unsigned long *)&ctx->sp;
  case BPF_USDT_REG_PC: return (unsigned long *)&ctx->reg_pc;
  default: return NULL;
  }
#else
  #error "Unsupported architecture for USDT"
#endif
}

// Helper function to get spec_id from context
static EBPF_INLINE int __bpf_usdt_spec_id(struct pt_regs *ctx)
{
  // We primarily use BPF cookies when available (kernel 5.15+)
  // For older kernels, fallback to IP-based lookup
  // Note: bpf_get_attach_cookie is not available in this environment,
  // so we always use IP-based lookup
  u64 ip           = (u64)ctx->reg_pc;
  u32 *spec_id_ptr = bpf_map_lookup_elem(&__bpf_usdt_ip_to_spec_id, &ip);
  return spec_id_ptr ? *spec_id_ptr : -1;
}

// libbpf-compatible function to fetch USDT arguments
static EBPF_INLINE UNUSED int bpf_usdt_arg(struct pt_regs *ctx, u64 arg_num, long *res)
{
  struct bpf_usdt_spec *spec;
  struct bpf_usdt_arg_spec *arg_spec;
  unsigned long val;
  unsigned long *reg_ptr;
  int err, spec_id;

  *res = 0;

  spec_id = __bpf_usdt_spec_id(ctx);
  if (spec_id < 0)
    return -1;

  spec = bpf_map_lookup_elem(&__bpf_usdt_specs, &spec_id);
  if (!spec)
    return -1;

  if (arg_num >= BPF_USDT_MAX_ARG_CNT || arg_num >= spec->arg_cnt)
    return -1;

  arg_spec = &spec->args[arg_num];

  // Read all fields into local variables to help BPF verifier
  u32 arg_type    = arg_spec->arg_type;
  u64 val_off     = arg_spec->val_off;
  u8 reg_id       = arg_spec->reg_id;
  bool arg_signed = arg_spec->arg_signed;
  s8 arg_bitshift = arg_spec->arg_bitshift;

  switch (arg_type) {
  case BPF_USDT_ARG_CONST:
    // Arg is just a constant ("-4@$-9" in USDT arg spec)
    val = val_off;
    break;
  case BPF_USDT_ARG_REG:
    // Arg is in a register (e.g, "8@%rax" in USDT arg spec)
    // Use switch to map register ID to pt_regs field
    reg_ptr = __bpf_usdt_get_reg_ptr(ctx, reg_id);
    if (!reg_ptr)
      return -1;
    val = *reg_ptr;
    break;
  case BPF_USDT_ARG_REG_DEREF:
    // Arg is in memory addressed by register, plus some offset
    reg_ptr = __bpf_usdt_get_reg_ptr(ctx, reg_id);
    if (!reg_ptr)
      return -1;
    val = *reg_ptr;
    err = bpf_probe_read_user(&val, sizeof(val), (void *)val + val_off);
    if (err)
      return err;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    val >>= arg_bitshift;
#endif
    break;
  default: return -1;
  }

  // Cast arg from 1, 2, or 4 bytes to final 8 byte size
  val <<= arg_bitshift;
  if (arg_signed)
    val = ((long)val) >> arg_bitshift;
  else
    val = val >> arg_bitshift;
  *res = val;
  return 0;
}
