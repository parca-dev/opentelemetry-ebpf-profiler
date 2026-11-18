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
transiently. Metadata caches remain unbounded, and so do the descriptors held by
file-backed sources: one per distinct file-backed cubin.

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
