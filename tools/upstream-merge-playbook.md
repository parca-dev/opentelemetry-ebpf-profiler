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

Start in a clean worktree on `origin/main`:

```bash
git fetch upstream
git checkout -b <some-tmp-branch> origin/main
tools/upstream-merge.sh --no-smoke
```

The script creates `upstream-merge`, binary-searches the unmerged upstream
commits, merges the maximal auto-resolvable prefix, and stops before the
first conflict it can't handle. Stopping output looks like:

```
>>> Branch upstream-merge: merged 12 of 127 upstream commits
!!! Stopped before: 64a21c56 bpf: rename field offtime to value (#1369)
!!! 115 commit(s) remain and need manual attention
```

Resolve that one commit by hand (see the decision matrix below), commit, then
drive the script forward by pointing `ORIGIN_REF` at the new HEAD:

```bash
git branch -D progress 2>/dev/null
git checkout -b progress
git branch -D upstream-merge
tools/upstream-merge.sh --no-fetch --no-smoke upstream/main progress
```

Loop until `git log upstream/main ^HEAD` is empty.

`--no-smoke` is recommended because the smoke test (`make test`) is slow and
its failures usually point at Go-side breakage caused by an earlier merge that
needs a follow-up, not at the merge currently being probed. Run `make test`
once at the end instead.

## What the script auto-resolves

Three things, all listed in the BPF/go.mod regexes near the top of the script:

- `support/ebpf/tracer.ebpf.{amd64,arm64}` — take `theirs`, then rebuild from
  the merged C sources.
- `go.mod` / `go.sum` — take `theirs`, then `go mod tidy`.
- Anything else where rerere has cached a clean resolution from a prior run.

The third one is why `rerere.enabled` and `rerere.autoUpdate` must both be on.
The script sets them with `--local` during preflight, but it's worth knowing
why: `autoUpdate=false` leaves rerere-resolved files in `UU` state, so
`all_auto_resolvable` rejects them as non-auto-resolvable and the script bails
on what would otherwise be a clean batch.

## Per-stop checklist

When the script stops, the workflow at each stop is the same:

1. `git merge --no-commit --no-edit <next-sha>` — see what conflicts come up.
2. Resolve each conflicting file (see decision matrix).
3. `git checkout --theirs support/ebpf/tracer.ebpf.{amd64,arm64}` and
   `make -C support/ebpf amd64 && make -C support/ebpf arm64`.
4. If `metrics/metrics.json` changed: `go generate ./metrics/...`.
5. If `support/types_def.go` changed: `(cd support && ./generate.sh)` and copy
   `types_gen.go` over `types.go`. Never edit `support/types.go` directly.
6. `git add -u` and verify with `CGO_ENABLED=1 go vet ./tracer ./support ...`
   (the packages touched by the merge).
7. Commit with `git -c user.email=... -c user.name='...' commit -s --no-edit`
   to preserve the auto-generated `Merge commit '<sha>' into upstream-merge`
   message. **No `Co-Authored-By: Claude` trailers** — this repo follows the
   OTel community policy of human-only attribution.

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
- **`increment_metric` definition** — parca has it in `support/ebpf/util.h`,
  not `tracemgmt.h`. When upstream adds it to `tracemgmt.h` as part of an
  unrelated relocation patch, drop their addition; keep ours in `util.h`.

### `support/ebpf/native_stack_trace.{ebpf.c,h}`

Parca split the body of `native_stack_trace.ebpf.c` out into the `.h`. When
upstream modifies the `.ebpf.c` body:

- Take `--ours` on `native_stack_trace.ebpf.c` (the file is essentially
  `#include "native_stack_trace.h"` now).
- Apply upstream's actual content changes to the corresponding place in
  `native_stack_trace.h`.

### `support/ebpf/types.h` — `UnwindState` register slots

Parca keeps `r14` on x86_64 (LuaJIT DISPATCH register). When upstream
adds/removes other slots (`rdi`/`r8` for vfork support, etc.), merge their
additions but keep `r14`.

### `metrics/metrics.json` and `metrics/ids.go`

Edit `metrics.json`; never hand-edit `ids.go`. Run `go generate ./metrics/...`
to regenerate.

**Metric ID policy**: parca-only metric IDs always live past upstream's IDMax.
When upstream lands new metrics that collide with parca's range, the upstream
metrics keep their authoritative IDs and parca's get renumbered to come after
them. Then `jq --indent 2 'sort_by(.id)' metrics/metrics.json` to keep the
file in ID order. The BPF `metricID_*` C enum positions don't change in this
swap — `MetricsTranslation` maps slot → Go symbol, not slot → Go value, so no
BPF blob rebuild is needed.

### `support/types_def.go` ↔ `support/types.go`

`types.go` is generated from `types_def.go` via cgo godefs. Edit
`types_def.go` for any C-enum additions, then:

```bash
(cd support && ./generate.sh)   # diffs generated vs current
cp support/types_gen.go support/types.go   # if the diff is what you wanted
rm -rf support/_obj support/types_gen.go
```

### Upstream "upstreams" of parca PRs

When upstream lands a PR that originally came from parca (custom labels,
dlopen-uprobe, python+native combo, fix-stale-go-label, native r28 fallback),
prefer the parca-fork version of the file — it usually has post-review
refinements upstream didn't pick up. Skip upstream's additions if parca has
the equivalent elsewhere (e.g. `go_support.h::get_go_m_ptr` already covers
`go_get_*` from upstream #1456).

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
