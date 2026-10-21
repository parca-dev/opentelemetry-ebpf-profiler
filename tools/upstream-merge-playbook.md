# Upstream merge playbook

This is the operator's manual for `tools/upstream-merge.sh`. The script handles
the easy parts (binary-searching for the maximal clean prefix, rebuilding BPF
blobs, accepting upstream's `go.mod`/`go.sum`). This document covers the bits
you have to bring: how to drive the script iteratively, what to look for at
each stopping point, and the parca-specific decisions that come up nearly every
cycle.

## When to use

Each upstream merge cycle: bring `parca-dev/opentelemetry-ebpf-profiler`'s
`main` up to a recent `open-telemetry/opentelemetry-ebpf-profiler` `main`,
landing as a single PR with one merge commit per resolved batch.

## Quick start

Start in a clean worktree on `origin/main`. Name the branch after the upstream
PR you are merging up to, so it can't collide with an older cycle's
`upstream-merge` branch still checked out in another worktree:

```bash
git fetch upstream
make test-deps          # once: test fixtures (pfelf, golabels, …) the tests need
tools/upstream-merge.sh --branch upstream-merge-2017
```

The script creates the branch off `origin/main`, binary-searches the
unmerged upstream commits, merges the maximal auto-resolvable prefix, and
stops before the first conflict it can't handle. Stopping output looks like:

```
>>> Branch upstream-merge: merged 12 of 127 upstream commits
!!! Stopped before: 64a21c56 bpf: rename field offtime to value (#1369)
!!! 115 commit(s) remain and need manual attention
```

Resolve that one commit by hand (see the decision matrix below), commit on
`upstream-merge`, then re-run:

```bash
tools/upstream-merge.sh --no-fetch --branch upstream-merge-2017
```

The script detects the existing branch, continues from its tip, and merges
the next auto-resolvable prefix. Loop until it reports "Fully merged with
upstream/main".

Pass `--fresh` if you want to discard the branch and start over from
`ORIGIN_REF` (e.g., after a botched iteration you'd rather redo).

Alternative to hand-doing `git merge` after each stop: pass
`--leave-conflicted`. The script merges the clean prefix as usual, then
attempts the next blocking commit itself, applies whatever auto-resolvers
apply (BPF blobs, go.mod, metrics, errors.h), and leaves the remaining
files unmerged in the working tree. Finish with `git add … && git commit`
and re-run.

The default smoke test is fast (seconds) and stays on: `go vet` type-checks
every package including tests without linking, which catches upstream API
changes that fork-only code uses but that merged without a textual conflict;
and `support/generate.sh` checks `support/types.go` is what upstream's
generator produces. `--full-smoke` adds `make test`, which needs the Rust
`symblib-capi` lib (`make rust-components`); run it once at the end.

## What the script auto-resolves

Everything in this list is handled by `auto_resolve` inside the script; the
regexes at the top define what counts as auto-resolvable and drive the probe
decision. The playbook's decision matrix below is now mostly reference — the
script does the mechanical work.

- `support/ebpf/tracer.ebpf.{amd64,arm64}` — take `theirs`, then rebuild from
  the merged C sources (`make -C support/ebpf amd64 && … arm64`).
- `support/ebpf/errors.h` — regenerated from `errors.json` and clang-formatted
  (also re-emitted after every BPF rebuild since the codegen output is
  unformatted). Requires `clang-format-17` on `PATH` (override with
  `CLANG_FORMAT=…`).
- `go.mod` / `go.sum` — take `theirs`, then `go mod tidy`.
- `internal/tools/go.mod` / `.sum` — take `theirs` verbatim (upstream's tools
  module is a thin shell; parca's app deps live in the root module).
- `metrics/metrics.json` — content-aware 3-way merge via `jq`: keep base
  entries, append upstream's new entries first (their assigned IDs win),
  append parca's new entries after (renumbered past upstream's max). Requires
  `jq`.
- `support/ebpf/types.h`, `support/types_def.go` — text conflicts resolved
  "theirs first, ours after" via a small awk script (works for the metric-ID
  and UnwindState-field cases; if you get anything weirder, land it by hand).
- `metrics/ids.go`, `support/types.go` — regenerated from `metrics.json` /
  `types_def.go` after those sources are merged. Never hand-edit either.
- Anything else where rerere has cached a clean resolution from a prior run.

The rerere path is why `rerere.enabled` and `rerere.autoUpdate` are set with
`--local` during preflight: `autoUpdate=false` would leave rerere-resolved
files in `UU` state, so `all_auto_resolvable` would reject them as
non-auto-resolvable and the script would bail on what could have been a
clean batch. Script-internal probes still override with
`-c rerere.enabled=false` so probing stays deterministic; hand-resolves done
between iterations still record.

## Per-stop checklist

When the script stops, the workflow at each stop is the same:

1. `git merge --no-ff --no-edit <next-sha>` — see what conflicts come up.
2. Resolve each conflicting file (see decision matrix). Resolve **hunks**, not
   files: `git checkout --theirs <file>` replaces the whole file and silently
   drops every fork-only line in it, not just the conflicting ones. If you did
   it by mistake, `git checkout -m <file>` restores the conflict markers.
3. `git add` the resolved sources, then `tools/upstream-merge.sh --regen`. It
   regenerates `metrics/ids.go` and `support/types.go`, rebuilds both BPF blobs
   (taking either side of a conflicted blob first), re-emits `errors.h`,
   stages all of them, and runs the smoke test. Never hand-edit `types.go`,
   and don't hand-run `cgo -godefs` either: upstream's `generate.sh` passes
   flags (`-DEBPF_TRACE_HEADER_ONLY` since #1914) that a bare invocation
   misses, giving a different `Trace` layout.
4. Run the unit tests of the packages the merge touched (`go test ./tracer/
   ./interpreter/<x>/ ./tools/coredump/ …`). vet only type-checks; a fork test
   that depends on fork-only sizes broke at #1849 and went unnoticed for six
   merges because nothing ran it.
5. Commit with `git -c user.email=... -c user.name='...' commit --no-edit`
   to preserve the auto-generated `Merge commit '<sha>' into upstream-merge`
   message. **No `Co-Authored-By: Claude` trailers** — this repo follows the
   OTel community policy of human-only attribution. Don't pass `-s` either:
   this repo doesn't gate on DCO, so the `Signed-off-by` trailer is just noise.
   Commits are signed cryptographically via `commit.gpgsign`, which is a
   different thing from `-s` (`--signoff`) — verify with `git log --show-signature`
   or `git log --format='%h %G?'`.

### Rebuilding the BPF blobs

The blobs are checked in, and CI (`.github/workflows/unit-test-ebpf.yml`)
rebuilds them in a pinned `otel/opentelemetry-ebpf-profiler-dev` image and
fails on any byte difference, with no useful diff. The script rebuilds with
whatever clang is on `PATH`. If the blob check fails, rebuild in CI's image:

```bash
docker run --rm --platform linux/arm64 --entrypoint bash -v "$PWD:/src" -w /src \
  otel/opentelemetry-ebpf-profiler-dev:latest@sha256:585409de39191c201f91a8e6ec5294556c8f21c7d2ce0b0f96e838f27e399f82 \
  -lc "git config --global --add safe.directory /src; make -C support/ebpf amd64 arm64"
```

Use `--platform linux/arm64` on an arm64 host, even though it builds the amd64
object too: clang cross-compiles it, while the amd64 image crashes under qemu
(the Go runtime dies, `go list` include paths collapse, and the build cannot
find `cupti_bpf.h`). On an amd64 host use `linux/amd64`.

## Decision matrix for recurring conflicts

These show up every cycle. Defaults assume the parca fork's behavior should
survive unless noted.

### `support/ebpf/tracemgmt.h`

- **`RATELIMIT_ACTION_NONE` early-return** — always keep. The dlopen-uprobe
  path depends on it; merging it into upstream's `RATELIMIT_ACTION_RESET`
  early-return block (one combined `||`) is the canonical resolution.
- **`normalize_pac_ptr` definition** — parca keeps the canonical definition
  near the top of the file; if upstream relocates or duplicates it, accept
  upstream's relocation and verify there's still only one definition.
- **`increment_metric`'s `DEBUG_PRINT`** — commented out in parca, live
  upstream. `DEBUG_PRINT` is compiled in and gated at runtime, so it costs
  instructions at every call site. `f8ee2110` cut it together with the prints
  in `python_tracer.ebpf.c` and the `native_stack_trace.h` steps it inlines, to
  fit the Python unwinder under the verifier after parca raised its unwind
  limits (`f1c902b0`). Keep ours on conflict; dropping it needs a distro-qemu
  run.

### `support/ebpf/native_stack_trace.{ebpf.c,h}`

Parca split the body of `native_stack_trace.ebpf.c` out into the `.h`. When
upstream modifies the `.ebpf.c` body:

- Take `--ours` on `native_stack_trace.ebpf.c` (the file is essentially
  `#include "native_stack_trace.h"` now).
- Apply upstream's actual content changes to the corresponding place in
  `native_stack_trace.h`.

### `support/ebpf/types.h` — `UnwindState` register slots

Parca keeps `r14` on x86_64 (LuaJIT DISPATCH register). The script's
"theirs first, ours after" swap-merge preserves both sides' field additions
(upstream's new registers land before parca's), so `r14` survives
automatically. If upstream ever *removes* a slot parca depends on, the swap
merge won't catch that — you'd have to notice in review.

### `metrics/metrics.json` and `metrics/ids.go`

Handled by the script (see "What the script auto-resolves"). Never hand-edit
`ids.go`; if you need to edit `metrics.json` outside a merge, run
`go generate ./metrics/...` afterwards.

**Metric ID policy** (what the auto-resolver encodes): parca-only metric IDs
always live past upstream's IDMax. Upstream keeps its assigned IDs; parca's
are renumbered to come after. `MetricsTranslation` maps slot → Go symbol,
not slot → Go value, so renumbering doesn't require a BPF blob rebuild.

### `support/types_def.go` ↔ `support/types.go`

`types.go` is generated from `types_def.go` via cgo godefs. The script
handles the swap-merge of `types_def.go` and regenerates `types.go` (inlined,
because `support/generate.sh` runs `go fmt` on a file that still has conflict
markers, but using the exact `cgo -godefs` command line grepped out of
`generate.sh`). Only touch this by hand if the auto-resolver produced something
weird — in which case edit `types_def.go` and run
`tools/upstream-merge.sh --regen`.

### Silent deletions: clean merges that drop fork behavior

The most dangerous merges have no conflict at all. When upstream deletes or
restructures code the fork extends, and the fork's lines in that region match
the merge base, git applies the deletion cleanly and the fork feature is
gone. #1907 (variable-length Trace data) did this three times in one merge:
the `custom_labels` decode in `tracer.go`, `CustomLabelsArray` in `types.h`,
and the `trace->custom_labels.len = 0` reset in `get_pristine_per_cpu_record`.
#2004 (apmint removal) did it again with the fork's apmint loader in
`processmanager/execinfomanager` (vet caught that one, because the package
was deleted).

For any upstream PR that rewrites a structure fork features hook into
(the `Trace` struct, `loadBpfTrace`, `unwind_stop`, `collect_trace`,
`TraceEventMeta`), diff the merge against its first parent for removed fork
lines:

```bash
git diff <merge>^1 <merge> -- tracer/ support/ebpf/ | grep '^-' | grep -iE 'custom|cuda|luajit|parca'
```

and run the fork feature's tests (`customlabelstest`, `interpreter/gpu`,
`interpreter/luajit`, coredump).

### Trace collection API (#1915)

`collect_trace(ctx, origin, pid, tid, leader, ts, value, cuda_id)` is gone.
Upstream split it into `prepare_trace` → optional `push_context_values` →
`unwind_trace(ctx, record, kernel_frames)`, and `collect_trace` is now a
no-value convenience wrapper. The fork's CUDA probe uses the split API
directly: `prepare_trace`, `push_kernel_frames`, push the `CUDA_KERNEL` frame,
then `unwind_trace(ctx, record, false)`. That keeps `tracemgmt.h` free of
`cuda_id`. On the Go side `TraceEventMeta.Value` became `ContextValues
[]uint64` (aliases a pooled trace; don't retain), and `TypeMetadata` has
`SampleTypes` plus a required `AppendValues`.

### `support/ebpf/` header conventions (#1995)

`u64` is now `unsigned long`, so `DEBUG_PRINT` formats are `%lx`/`%lu`/`%ld`,
not `%llx`. Fork-only BPF code hits this as `-Wformat` errors after the
merge. Headers use `#pragma once`; when a conflict is just a fork addition
before the old `#endif // OPTI_*_H`, keep the addition and drop the `#endif`.

### nodev8

Fork-only pieces of `interpreter/nodev8/v8.go` are the JS debug-ID support
(`fileToDebugID`, `pid`, `appendFrame`'s `FileID`/`Mapping`, `debugid.go`) and
the Node custom-labels data (`isolateSym`, `cpedOffset`, `wrappedObjectOffset`,
the `NodeVersion`/`CurrentIsolate` symbols, `loadNodeClData`, and the matching
`V8ProcInfo` fields). Everything else should match upstream: take theirs and
re-add those. Leaptiering (Node 24) landed upstream in #1917; the fork no
longer carries its own.

### External BPF headers

`parca-dev/usdt` and `parca-dev/parcagpu` headers are included with
`-isystem`, so upstream's stricter warnings (#1910's `-Wsign-conversion`)
don't fail the build on code we don't own here. Fix the warnings in those
repos and switch back to `-I` when they release.

### LuaJIT upstreaming in progress

Upstream is landing parca's LuaJIT unwinder in pieces (#1929 brought the
JIT-region tracking). When a piece lands, adopt upstream's names and shapes
for it (`LJJitMarker`, `regionKey`-keyed `jitRegions`) and keep only the parts
upstream doesn't have yet, so each subsequent piece merges with less friction.

### Upstream "upstreams" of parca PRs

When upstream lands a PR that originally came from parca (custom labels,
dlopen-uprobe, python+native combo, fix-stale-go-label, native r28 fallback),
check whether the parca-fork version still has post-review refinements upstream
didn't pick up. If it does, keep it; if upstream's has caught up or overtaken
it, take upstream's and delete ours. Carrying a duplicate "because it is ours"
is how the delta grows.

`go_support.h::get_go_m_ptr` was the worked example of getting this wrong: it
was kept as parca's equivalent of upstream's `go_get_*` (#1456, moved into
`go_runtime.h` by #1626), long after upstream's version had become a strict
superset — same success path, plus an r28 fallback on the paths where ours
returned NULL. It is gone now; use `go_runtime.h::go_get_m_ptr`.

### Rename cascades

Upstream periodically renames things parca code participates in. The recurring
ones so far:

- `off_cpu_time → value` (#1369): also rename `TraceMeta.OffTime → Value` in
  `interpreter/gpu/`.
- `ReadVirtualMemory → ReadAt` (#1384): parca's nodev8 has extra call sites
  upstream's PR doesn't touch.
- Perf reader → ringbuf reader (#1339): drop `TraceBufferSizeMultiplier`
  (perf-specific) and `lostEventsCount`; `loadBpfTrace` no longer takes a
  `CPU` arg.
- `Trace.Hash` removed (#1518): drop explicit `traceutil.HashTrace` calls;
  `maybeNotifyAPMAgent` takes `*libpf.Trace` directly.
- `Value` → `ContextValues`, `SampleType`/`SampleUnit` → `SampleTypes`
  (#1915): `interpreter/gpu` sets `ContextValues: []uint64{v}` on the
  synthesized GPU samples.
- `tail_call(ctx, next)` → `return tail_call(ctx, record, next)` (#1962):
  fork unwinders (LuaJIT) must return its value.
- `ApmSpanID`/`ApmTraceID` → `SpanID`/`TraceID`, `APMServiceName` removed
  (#2004).
- `OpenMappingFile` returns `fs.File`, ELF helpers take an `fs.FS` (#1900):
  `interpreter/gpu/cubin.go` implements the file; downstream parca-agent
  callers need the same change.

When in doubt: grep parca-only files (`interpreter/gpu/`, `interpreter/cuda*`,
`interpreter/customlabels/`, `interpreter/oomwatcher/`) for the old name.

## Filing the PR

Branch name convention: `upstream-merge-<NNNN>` where `NNNN` is the highest
upstream PR number included.

PR title: `upstream merge: N merges through #NNNN [+ ...]`.

PR body should call out:
- Notable upstream PRs folded in and what parca-side surgery they required.
- Any metric ID renumbering done this cycle.
- Outstanding upstream commits that landed after the branch was cut.
- Pre-existing vet/build issues that aren't caused by the merge.

## Things that have been wrong before

A list of mistakes from prior cycles so future-you can recognize them:

- **Pushing upstream's new metric IDs to the end of the range instead of
  parca's.** Always: upstream owns the lower IDs, parca's stuff goes at the
  end past upstream's IDMax.
- **Editing `support/types.go` directly** instead of `types_def.go`. The
  generator's diff will tell you, but only after you've made the wrong edit.
- **Forgetting `git config rerere.autoUpdate true`.** The script now sets
  this, but if you're resolving by hand outside the script, do the same.
- **Putting `Co-Authored-By: Claude` or "Generated with Claude Code" in PR
  bodies.** OTel-adjacent repos don't take AI attribution. The user is the
  author.
- **Running `git merge upstream/main` once and trying to resolve everything in
  one merge commit.** The script's batching produces a cleaner history and is
  way more debuggable when something breaks.
- **`git checkout --theirs` on a file with fork-only lines** (to "take
  upstream's version of the conflict"). It takes the whole file. Resolve the
  hunks; `git checkout -m <file>` brings the markers back.
- **Regenerating `types.go` with a bare `go tool cgo -godefs types_def.go`.**
  Upstream's `generate.sh` adds flags; use `--regen`.
- **Trusting vet alone between merges.** It doesn't run tests. Run the
  touched packages' tests at each stop.
- **Deleting and recreating `upstream-merge` between iterations.** Loses any
  remote tracking config on the branch and is just ceremony. The script now
  continues an existing branch by default; use `--fresh` only when you
  actually want to restart.
