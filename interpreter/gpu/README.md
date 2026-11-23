# GPU profiling design notes

This package attaches to parcagpu's USDT probes, correlates GPU activity with
CPU traces and builds PC-sampling profiles. The agent consumes the event stream
and reports cubin debug files.

## Cubin identity and instruction lookup

PC samples need cubin metadata even when instruction bytes are unavailable.
`CubinInfo` keeps the FileID, SM version and executable-section names, addresses,
sizes and file offsets, keyed by CUPTI CRC. The agent computes FileID from the
unmodified loaded image, not from the CRC or a filename.

The agent uses `ParseCubinELFMetadata` to avoid retaining executable-section
bytes. `decodeInstruction` reads 16 bytes from an optional `CubinFileSource`
or the bounded memory cache and uses the SM-specific SASS opcode table. The
legacy `ParseCubinELF` API still populates section bytes for callers that need them.

Missing instruction bytes remove only the `cuda_sass_instruction` label.
FileID, kernel identity, PC offsets, stall reasons and counts remain available.
Store identity metadata even without a file source, because PC samples with no
cached cubin are dropped.

## Original files and lifetime

The shim supplies a canonical filename only for module resource callbacks
inside a synchronous `cuModuleLoad` call. `MatchCubinFile` accepts the hint only
after comparing the entire file with the loaded image. PTX is not the executed
cubin, and a containing fatbinary or shared library is not the standalone image.
There is no directory scanning, guessed cache filename or agent-owned disk cache.

`MatchCubinFile` opens the file once, through the target process's root via
`process.Open`, which uses `openat2` root confinement, rejects magic links and
checks for regular files. It must run while the process is alive. The source
keeps that descriptor, so it holds the inode rather than the path. Instruction
lookups and uploads both read through it, and keep working after the process
exits, its mount namespace is torn down or the path is unlinked or replaced.
The descriptor closes when the source is unreachable and garbage collected.

The source retains no code bytes. It keeps the size and SHA-256 hashes of 4 KiB
blocks, about 0.8% of the image. FileID samples only the image's beginning and
end, so it cannot prove an exact match, and timestamps cannot detect writes
within one timestamp tick, so every read validates its blocks against the
hashes. In-place writes or truncation of the held inode remove enrichment and
fail uploads without dropping identified samples. Uploads validate the whole
image before use and validate blocks on subsequent reads.

ELF `e_version` normalization happens while reading metadata or upload data.
It changes neither the application file nor the bytes used to compute FileID.
Upload naming and identity stay unchanged.

## Memory-only cubins

Without a usable original file, `CacheCubinCode` admits the immutable raw image
into a byte-bounded LRU, separate from identity metadata. The default budget is
zero, so memory-only instruction lookup is off unless the agent enables it with
`--gpu-cubin-cache-size`. File-backed instruction lookup remains enabled. The
budget counts whole backing buffers, not just executable sections.
Oversized images are skipped without evicting useful entries. Successful
instruction reads refresh recency; duplicate metadata notifications do not.
New admissions evict the least recently sampled entries until they fit. There
is no time-based expiration without cache pressure.

While the cache is enabled, each memory-only cubin's origin (PID, pointer, size
and a SHA-256 of the image) is kept with its metadata. A sample that misses an
evicted image schedules one background reread from `/proc/<pid>/mem`, at most
once per second per cubin, and admits it only if the hash still matches, so
memory reused by an unloaded module or a recycled PID is rejected. That sample
reports without a mnemonic; later ones decode once it is resident. Images larger
than the budget are not reread.

The shim deduplicates module loads by CRC using reference counts. It replays
loaded cubins when consumers join and roughly every 30 seconds during CUDA
callbacks. A replay updates the origin but does not readmit an evicted image,
so replays in load order cannot churn the cache; sampling decides what stays.
The agent rereads replayed images to refresh sources and retry upload reporting.

The legacy upload adapter can retain the same image independently of this cache
in a queued reporter callback. Evicting code does not cancel uploads or free
buffers still needed by them. File-backed sources retain a descriptor but no
image bytes, but the initial process-memory read still allocates the whole image
transiently. Metadata and the descriptors held by file-backed sources are not
size-bounded: they last as long as some process holds the cubin, as below.

## Unloads and process exit

`CubinInfo`, the cached image and its origin are keyed by CRC and shared by every
process that loads the same cubin. The consumer calls `TrackCubinLoad` for each
load event and `HandleCubinUnloadedEvent` for each `cubin_unloaded` event, both
synchronously in ringbuf order. Loads are handled asynchronously, but the
ringbuf already orders one process's load before its unload. The shim reference
counts modules per process, so `cubin_unloaded` means the process unloaded its
last module with that CRC. Process exit, through `Detach`, releases everything
the process held, because most processes exit without unloading anything.

The last release does not drop the cubin. Samples taken before it can still be
in flight. A PC sample waits up to `maxEntryAge` for its correlation trace, the
shim can drain CUPTI's buffer after the unload probe fires, and samples are
handled on their own goroutines. Each of these looks up the cubin by CRC when it
reports. `MaybeClearAll` drops the metadata, the cached image and the origin once
no process has held the CRC for `cubinUnloadGrace` (twice `maxEntryAge`). A load
by any process during that time cancels the drop, and a later release starts a
new grace period. A sample that arrives after the drop is dropped with the usual
"not in cache" debug message. Queued uploads keep what they hold.

When the process whose memory the origin points to releases the cubin, rereads
move to another holder's copy. If no holder remains, rereads stop. The cached
image stays until the drop.

The eBPF side deletes the `(pid, crc)` entry from `cubin_seen` on unload, so a
reload in the same process is reported again. Exited processes still leave
their entries until LRU eviction. If a recycled PID loads the same CRC before
then, the load is deduplicated away, and after a drop that process's samples
lack the cubin. The shim fires `cubin_unloaded` before it removes the cubin from
its replay list. A replay racing an unload can therefore re-register the cubin
for that process until the process exits.

Cubins never passed to `TrackCubinLoad` are kept for the agent's lifetime, so
consumers that predate it behave as before.

## Device identity

Kernel timings, PC samples and NVTX events carry the CUDA ordinal, which
depends on the process's `CUDA_VISIBLE_DEVICES` and `CUDA_DEVICE_ORDER`. The
`device_info(ordinal, uuid, pciBusId)` probe fires on the first context on each
device and replays like `gpu_config`. It is not deduplicated in eBPF, so a replay
restores a mapping lost to a full ringbuf or a recycled PID.
`HandleDeviceInfoEvent` caches it per PID and ordinal, alongside `GpuConfig`.
`LoadDeviceInfo` and `PCSampleDeviceInfo` return it. `DeviceInfo.UUIDString`
formats the UUID the way nvidia-smi does (`GPU-…`), which matches the `hw.id`
of NVML metrics. `Detach` drops the PID's mappings.

## Loading-path coverage

- [Triton's compiler](https://github.com/triton-lang/triton/blob/main/python/triton/compiler/compiler.py)
  writes cubins to its cache but passes bytes to
  [`load_binary`](https://github.com/triton-lang/triton/blob/main/third_party/nvidia/backend/driver.c),
  which calls `cuModuleLoadData`. That path supplies no filename, including when
  used by PyTorch. Having a cache file on disk does not establish provenance.
- [PyTorch's generated CUDA C++ loader](https://github.com/pytorch/pytorch/blob/main/torch/_inductor/codegen/cuda/device_op_overrides.py)
  has a file-path overload calling `cuModuleLoad`. Standalone cubins can qualify
  when the callback is synchronous and the exact file remains accessible. Its
  embedded-data overload calls `cuModuleLoadData` and does not qualify.

`cuModuleLoadDataEx`, runtime linking and deferred loads supply no filename here.
Coverage depends on the loader used, not on the framework name.

## Host blocking calls

parcagpu's optional `cuda_blocking_call(startNs, endNs, cbid, deviceId,
weightNs)` probe reports CUDA API calls that blocked the calling thread:
synchronizes, synchronous copies, allocation and freeing, pinning, module
loading and graph instantiation. It fires inside the call, before the call
returns, so the CPU stack is the application's. parcagpu reports every call
blocked at least its threshold T with weight = duration, and a shorter call
with probability duration/T and weight T, so summed weights estimate total
blocked time without bias. The probe is off unless the process sets
`PARCAGPU_BLOCKING_CALLS`, or the agent sets `PARCAGPU_FEATURE_BLOCKING_CALLS`.

`cuda_blocking_call` in `cuda.ebpf.c` unwinds the stack at the probe, like
`cuda_correlation`, but needs nothing from `cupti_events`: everything the
sample needs is known at the probe. The trace's origin is
`ProfileTypeCudaBlocking` (`cuda_blocking_time`, nanoseconds), and it carries
three context values: the weight, which is the sample value, the call's own
duration, and the signed cbid with the device in the high 32 bits. It has no
kernel frames, since a uprobe's kernel stack is only the trap. In
`cuda_probe` it is cookie 14, after `device_info` (12) and `cubin_unloaded`
(13). It needs no `cuda_progs` slot or event type.

`DecorateBlockingTrace` labels the trace before it is reported: `cuda_api`
with the function name, and `cuda_device` unless parcagpu didn't know the
device. `CbidName` maps cbids, positive for the runtime API and negative for
the driver API, through `cbid_names.go`, generated by `gencbids` from CUPTI's
cbid headers. Runtime names drop CUPTI's version suffix (`cudaMalloc_v3020`
is `cudaMalloc`); driver names are the exported symbols (`cuMemAlloc_v2`). A
cbid newer than the table is named `cuda_runtime_cbid_N` or
`cuda_driver_cbid_N`; regenerate the table from newer headers to name it.

## Probe compatibility

The shim keeps `cubin_loaded(crc, ptr, size)` unchanged and also fires the optional
`cubin_loaded_file(crc, ptr, size, path)`, including during metadata replay. An
empty path is normal for memory-only modules. The profiler attaches to the
file-bearing probe when present and otherwise to the legacy probe, never both.
Legacy event layouts and dispatch cookies keep their meanings. The optional
event uses a separate discriminator and cookie.

| Agent | Shim | Mnemonics | Upload source |
| --- | --- | --- | --- |
| Old | Old | In-memory decode | In-memory image |
| Old | New | Unchanged legacy decode | In-memory image |
| New | Old | Off by default; in-memory if cache enabled | In-memory image |
| New | New, matching original | Original-file decode | Original file |
| New | New, no usable original | Off by default; in-memory if cache enabled | In-memory image |

All combinations preserve FileID, kernel identity, PC offsets, stalls and counts.
New agents omit mnemonics when code is unavailable or outside the memory budget.
Agent and shim upgrades do not require a lockstep rollout.

`device_info` and `cubin_unloaded` are optional, like every probe after the
kernel-timing one. A shim without `device_info` attaches as before, and
`LoadDeviceInfo` reports nothing, so consumers keep labeling by ordinal. A shim
without `cubin_unloaded` releases cubins only when their processes exit.
Each probe has its own event type, 11 and 12, and its own
`cuda_probe` cookie. Neither needs a tail call.

`cuda_blocking_call` is optional. A library without it attaches as before,
and an agent without it ignores it. With both, the probe fires only when the
process or agent turns it on.

## Shim log

parcagpu's `log(level, code, timeNs, component, message)` probe carries its
log channel: debug, info, warn and error records (levels 1 to 4), at or above
the process's `PARCAGPU_LOG_LEVEL` (info by default). `cuda_log` copies each
into a `log_event` (event type 13, cookie 15), and `HandleLogEvent` logs it at
its level as `[parcagpu] pid=N component: message`.

Most of what goes wrong in the shim happens while the CUDA driver loads it,
before the profiler has attached to a new process. parcagpu keeps its last 64
info-and-above records and fires them again half a second after a consumer
attaches to the probe, with their original `timeNs`. A record can therefore
arrive more than once, after a profiler restart or a second consumer such as
bpftrace attaching. `HandleLogEvent` drops a record whose (pid, `timeNs`) it
has already seen.

`log` supersedes the older `error(code, message, component)` probe. A shim with
`log` fires its warnings and errors on both, so the profiler attaches `log`
when the library has it and falls back to `error` only when it doesn't. An
older agent keeps receiving warnings and errors through `error`.
