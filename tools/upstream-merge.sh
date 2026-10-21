#!/usr/bin/env bash
#
# upstream-merge.sh — keep origin/main up to date with upstream/main
#
# Finds the merge base, identifies all upstream commits past it, and
# merges the largest prefix that doesn't require human intervention.
# After merging, a smoke test is run to verify the result; if it fails
# the script binary-searches for the last commit that passes.
#
# Auto-resolvable conflicts:
#   * support/ebpf/tracer.ebpf.{amd64,arm64} — rebuilt from merged sources
#   * support/ebpf/errors.h — regenerated from errors.json and clang-formatted
#   * go.mod / go.sum — accept upstream, then `go mod tidy`
#
# Everything else is considered a "real" conflict and the script stops
# before it, leaving you with the largest clean merge possible.
#
# Usage:
#   tools/upstream-merge.sh [options] [upstream-ref] [origin-ref]
#
# Options:
#   --no-fetch          Skip 'git fetch' (useful when you already fetched)
#   --no-smoke          Skip the post-merge smoke test
#   --leave-conflicted  After the clean prefix is merged, attempt the next
#                       blocking commit and leave any unresolved conflicts
#                       in the working tree for manual resolution. Auto-
#                       resolvable bits (BPF blobs, go.mod, metrics) are
#                       still applied. Exits 0 — you finish with
#                       `git add … && git commit`.
#   --fresh             Delete an existing working branch and start
#                       over from ORIGIN_REF.
#   --branch NAME       Working branch name (default: upstream-merge). Use a
#                       per-cycle name (e.g. upstream-merge-2017) when an
#                       older upstream-merge branch is still checked out in
#                       another worktree.
#   -h, --help          Show this help
#
# Defaults: upstream/main and origin/main.
#
# Iteration: if the working branch already exists, the script picks
# up from its tip so each run advances the same branch. Pass --fresh to
# discard prior progress and restart from ORIGIN_REF.

set -euo pipefail

# ── smoke-test commands ────────────────────────────────────────────────
# All must pass for a merge to be accepted.  Add more entries as needed.

SMOKE_CMDS=(
    "go test -run ^$ ./..."
    "make test"
)

# ── defaults & arg parsing ─────────────────────────────────────────────

UPSTREAM_REF="upstream/main"
ORIGIN_REF="origin/main"
DO_FETCH=true
DO_SMOKE=true
LEAVE_CONFLICTED=false
FORCE_FRESH=false
BRANCH="upstream-merge"

args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-fetch)         DO_FETCH=false; shift ;;
        --no-smoke)         DO_SMOKE=false; shift ;;
        --leave-conflicted) LEAVE_CONFLICTED=true; shift ;;
        --fresh)            FORCE_FRESH=true; shift ;;
        --branch)           BRANCH="$2"; shift 2 ;;
        -h|--help)          sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)                  args+=("$1"); shift ;;
    esac
done
if [[ ${#args[@]} -ge 1 ]]; then UPSTREAM_REF="${args[0]}"; fi
if [[ ${#args[@]} -ge 2 ]]; then ORIGIN_REF="${args[1]}"; fi

# ── helpers ────────────────────────────────────────────────────────────

log()  { printf '\033[1;34m>>>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERR\033[0m %s\n' "$*" >&2; exit 1; }

REPO_ROOT="$(git rev-parse --show-toplevel)"
GIT_DIR="$(git rev-parse --git-dir)"

BPF_BLOB_RE='^support/ebpf/tracer\.ebpf\.(amd64|arm64)$'
GOMOD_RE='^go\.(mod|sum)$'
TOOLS_GOMOD_RE='^internal/tools/go\.(mod|sum)$'

# Metrics-related files. parca-specific metrics live alongside upstream's; when
# upstream adds a new metric whose ID overlaps with one of ours, the convention
# is "upstream gets its assigned slot, parca shifts to come after". This applies
# uniformly to:
#   metrics/metrics.json    — source of truth, JSON 3-way merged by name
#   metrics/ids.go          — regenerated from metrics.json
#   support/ebpf/types.h    — text conflict, swap so theirs precedes ours
#   support/types_def.go    — text conflict, swap so theirs precedes ours
#   support/types.go        — regenerated from types_def.go via cgo -godefs
METRICS_JSON_RE='^metrics/metrics\.json$'
METRICS_GEN_RE='^(metrics/ids\.go|support/types\.go)$'
METRICS_SWAP_RE='^(support/ebpf/types\.h|support/types_def\.go)$'

# support/ebpf/errors.h is generated from tools/errors-codegen/errors.json (it's
# a build dependency of every .ebpf.o). The generator emits unformatted C while
# the committed file is clang-formatted, so every eBPF rebuild - and any text
# conflict on errors.h - leaves it dirty. We regenerate + clang-format it.
ERRORS_H_RE='^support/ebpf/errors\.h$'
# clang-format binary, matching support/ebpf/Makefile's default; override via
# the environment if your distro names it differently.
CLANG_FORMAT="${CLANG_FORMAT:-clang-format-17}"

# Print paths of unmerged (conflicting) files, one per line.
unmerged_files() {
    git diff --name-only --diff-filter=U
}

# Return 0 iff the given path is one auto_resolve knows how to handle.
is_auto_resolvable_path() {
    local f="$1"
    [[ "$f" =~ $BPF_BLOB_RE \
    || "$f" =~ $GOMOD_RE \
    || "$f" =~ $TOOLS_GOMOD_RE \
    || "$f" =~ $METRICS_JSON_RE \
    || "$f" =~ $METRICS_GEN_RE \
    || "$f" =~ $METRICS_SWAP_RE \
    || "$f" =~ $ERRORS_H_RE ]]
}

# Return 0 if every conflicting file is one we know how to auto-resolve.
all_auto_resolvable() {
    local f count=0
    while IFS= read -r f; do
        is_auto_resolvable_path "$f" || return 1
        ((count++))
    done < <(unmerged_files)
    # Must have at least one conflict to be "resolvable" (not an empty set).
    [[ $count -gt 0 ]]
}

# Ensure the repo is in a clean, non-merging state.  Aggressively
# removes stale lock files that a failed merge may leave behind.
reset_merge_state() {
    rm -f "$GIT_DIR/index.lock"
    git merge --abort 2>/dev/null || git reset --merge 2>/dev/null || true
    rm -f "$GIT_DIR/index.lock"
}

# Non-destructive merge probe: attempt the merge, check whether it's
# clean or auto-resolvable, then roll back.  Returns 0 = mergeable.
probe_merge() {
    local sha="$1"
    if git -c rerere.enabled=false merge --no-commit --no-edit "$sha" >/dev/null 2>&1; then
        reset_merge_state
        return 0
    fi
    local rc=1
    all_auto_resolvable && rc=0
    reset_merge_state
    return "$rc"
}

# Binary-search for the index of the last commit where probe_merge
# succeeds.  Prints the index to stdout, or -1 if none.
find_last_clean() {
    local lo=0 hi=$(($1 - 1)) result=-1 mid
    while [[ $lo -le $hi ]]; do
        mid=$(( (lo + hi) / 2 ))
        printf '\r  probing %d/%d …' "$((mid + 1))" "$1" >&2
        if probe_merge "${COMMITS[$mid]}"; then
            result=$mid
            lo=$((mid + 1))
        else
            hi=$((mid - 1))
        fi
    done
    printf '\n' >&2
    echo "$result"
}

# Resolve metrics/metrics.json conflicts using a content-aware 3-way merge.
#
# The metrics.json file is a JSON array of {description, name, type, field, id}
# objects, append-only by convention. When upstream and parca both add new
# entries at overlapping IDs, the resolution is:
#   1. Keep every entry from the merge base.
#   2. Append upstream's new entries first (preserving their assigned IDs).
#   3. Append parca's new entries next, renumbered to come after.
# Identified by name (not ID), so it's robust to either side renumbering.
resolve_metrics_json() {
    local f=metrics/metrics.json
    local base_json ours_json theirs_json
    base_json=$(git show ":1:$f")   || return 1
    ours_json=$(git show ":2:$f")   || return 1
    theirs_json=$(git show ":3:$f") || return 1

    jq -n \
        --argjson base   "$base_json" \
        --argjson ours   "$ours_json" \
        --argjson theirs "$theirs_json" \
        '
          ($base   | map(.name)) as $base_names
        | ($theirs | map(select((.name | IN($base_names[])) | not))) as $new_theirs
        | ($ours   | map(select((.name | IN($base_names[])) | not))) as $new_ours
        | ($base + $new_theirs) as $head
        | ($head | map(.id) | max) as $head_max
        | $head + ($new_ours
            | to_entries
            | map(.value + { id: ($head_max + 1 + .key) }))
        ' > "$f" || return 1
    git add "$f"
}

# Resolve a textual "ours after theirs" conflict (used for support/ebpf/types.h
# and support/types_def.go). For each <<<<<<<…=======…>>>>>>> block, emit the
# upstream content first, then ours. Comments and blank lines inside the block
# are preserved verbatim.
resolve_metrics_swap() {
    local f="$1"
    awk '
        BEGIN { state = 0 }
        /^<<<<<<< / { state = 1; head = ""; up = ""; next }
        /^=======$/ && state == 1 { state = 2; next }
        /^>>>>>>> / && state == 2 {
            printf "%s", up
            printf "%s", head
            state = 0
            next
        }
        state == 1 { head = head $0 "\n"; next }
        state == 2 { up   = up   $0 "\n"; next }
        { print }
    ' "$f" > "${f}.tmp" || return 1
    mv "${f}.tmp" "$f" || return 1
    git add "$f"
}

# Regenerate the generated metrics-related files from their sources. Called
# after metrics.json / types_def.go have been merged.
#
# Inlines support/generate.sh's logic rather than calling the script directly,
# because that script runs `go fmt .` on the support/ package — and at this
# point support/types.go still has conflict markers, which `go fmt` rejects.
regen_metrics() {
    ( cd "$REPO_ROOT" \
      && go run metrics/genids/main.go metrics/metrics.json metrics/ids.go \
    ) || return 1
    (
        cd "$REPO_ROOT/support" || exit 1
        # Start fresh: emit license header, then append cgo -godefs output.
        cat > types.go <<'HEADER'
// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

HEADER
        go tool cgo -godefs types_def.go >> types.go || exit 1
        # Set the correct package path (matches support/generate.sh).
        sed -i 's|^package support$|package support // import "go.opentelemetry.io/ebpf-profiler/support"|' types.go
        # Format the regenerated file (now that types.go is well-formed).
        go fmt . >/dev/null || exit 1
        rm -rf _obj/
    ) || return 1
    git add metrics/ids.go support/types.go
}

# Regenerate support/ebpf/errors.h from errors.json and clang-format it.
#
# errors.h is a generated file (the eBPF objects depend on it), but the codegen
# emits unformatted C whereas the committed copy is clang-formatted. So both a
# text conflict on errors.h and a plain rebuild (make -C support/ebpf) leave it
# dirty. Re-emit it from the already-merged errors.json, format, and stage it so
# it lands clean in the merge commit. errors.json itself is not auto-resolvable,
# so if it conflicts we never reach here (the script stops on it first).
regen_errors_h() {
    ( cd "$REPO_ROOT/support/ebpf" \
      && go run ../../tools/errors-codegen/main.go bpf errors.h \
      && "$CLANG_FORMAT" -i -style=file errors.h \
    ) || return 1
    git add support/ebpf/errors.h || return 1
}

# Resolve auto-resolvable conflicts in the working tree and commit.
# Uses explicit || return 1 so this is safe to call from condition
# contexts (e.g. inside an `if`) where set -e is suppressed.
auto_resolve() {
    local has_bpf=false has_gomod=false has_tools_gomod=false has_metrics=false has_errors=false f
    local -a conflicts
    mapfile -t conflicts < <(unmerged_files)

    for f in "${conflicts[@]}"; do
        case "$f" in
            support/ebpf/tracer.ebpf.*)                  has_bpf=true ;;
            support/ebpf/errors.h)                       has_errors=true ;;
            go.mod|go.sum)                               has_gomod=true ;;
            internal/tools/go.mod|internal/tools/go.sum) has_tools_gomod=true ;;
        esac
        if [[ "$f" =~ $METRICS_JSON_RE \
           || "$f" =~ $METRICS_GEN_RE \
           || "$f" =~ $METRICS_SWAP_RE ]]; then
            has_metrics=true
        fi
    done

    # ── go.mod / go.sum ────────────────────────────────────────────────
    if $has_gomod; then
        log "  go.mod/go.sum → accept upstream + go mod tidy"
        git checkout --theirs -- go.mod                              || return 1
        git checkout --theirs -- go.sum 2>/dev/null || true
        ( cd "$REPO_ROOT" && go mod tidy )                           || return 1
        git add go.mod go.sum                                        || return 1
    fi

    # ── internal/tools/go.mod / .sum ───────────────────────────────────
    # After upstream PR #1330 the tools module is a thin shell holding only
    # build-tool deps (golangci-lint, mdatagen, gotestsum, …). parca-specific
    # application deps live in the main go.mod, so taking theirs verbatim is
    # the right resolution — no tidy needed (and `go mod tidy -modfile=…`
    # from this repo's root produces ambiguous-import errors against the
    # public-published main module, which upstream's CI works around with
    # two `go mod edit -replace` directives that aren't needed here).
    if $has_tools_gomod; then
        log "  internal/tools/go.mod/sum → accept upstream verbatim"
        git checkout --theirs -- internal/tools/go.mod              || return 1
        git checkout --theirs -- internal/tools/go.sum 2>/dev/null || true
        git add internal/tools/go.mod internal/tools/go.sum         || return 1
    fi

    # ── metrics conflicts (parca always after upstream) ────────────────
    # Order: merge metrics.json + the textual files (types.h, types_def.go),
    # then regenerate ids.go and types.go from those sources.
    if $has_metrics; then
        log "  metrics.json/types.h/types_def.go → upstream first, parca after"
        for f in "${conflicts[@]}"; do
            if [[ "$f" =~ $METRICS_JSON_RE ]]; then
                resolve_metrics_json || return 1
            elif [[ "$f" =~ $METRICS_SWAP_RE ]]; then
                resolve_metrics_swap "$f" || return 1
            fi
            # ids.go / types.go are regenerated below, after sources are merged.
        done
        log "  regenerating metrics/ids.go and support/types.go"
        regen_metrics || return 1
    fi

    # ── BPF blobs ──────────────────────────────────────────────────────
    if $has_bpf; then
        log "  BPF blobs → rebuilding from merged sources"
        for f in "${conflicts[@]}"; do
            case "$f" in
                support/ebpf/tracer.ebpf.*)
                    git checkout --theirs -- "$f"                    || return 1
                    git add "$f"                                     || return 1
                    ;;
            esac
        done
        make -C "$REPO_ROOT/support/ebpf" amd64                     || return 1
        make -C "$REPO_ROOT/support/ebpf" arm64                     || return 1
        git add support/ebpf/tracer.ebpf.amd64 \
               support/ebpf/tracer.ebpf.arm64                       || return 1
    fi

    # ── errors.h (generated eBPF header) ───────────────────────────────
    # Run last: whether errors.h came in as a conflict (has_errors) or was just
    # regenerated-but-unformatted by the BPF rebuild above (has_bpf), re-emit and
    # clang-format it so it doesn't linger as a dirty file after the merge.
    if $has_errors || $has_bpf; then
        log "  errors.h → regenerate from errors.json + clang-format"
        regen_errors_h || return 1
    fi

    # Annotate the merge commit message.
    local merge_msg="$GIT_DIR/MERGE_MSG"
    if [[ -f "$merge_msg" ]]; then
        {
            cat "$merge_msg"
            echo ""
            echo "Auto-resolved:"
            if $has_gomod;       then echo "  - go.mod/go.sum: accepted upstream, ran go mod tidy"; fi
            if $has_tools_gomod; then echo "  - internal/tools/go.mod/sum: accepted upstream verbatim"; fi
            if $has_metrics;     then echo "  - metrics: upstream IDs preserved, parca renumbered after, generated files regenerated"; fi
            if $has_bpf;         then echo "  - BPF blobs: rebuilt from merged C sources"; fi
            if $has_errors || $has_bpf; then echo "  - errors.h: regenerated from errors.json and clang-formatted"; fi
        } > "${merge_msg}.tmp"
        mv "${merge_msg}.tmp" "$merge_msg"
    fi

    git commit --no-edit                                             || return 1
}

# Run every command in SMOKE_CMDS.  Returns 0 only if all pass.
run_smoke() {
    local cmd rc=0
    for cmd in "${SMOKE_CMDS[@]}"; do
        log "  smoke: $cmd"
        if ! ( cd "$REPO_ROOT" && eval "$cmd" ); then
            rc=1
            break
        fi
    done
    # `make test` rebuilds the eBPF, which regenerates support/ebpf/errors.h
    # (a generated file) unformatted, while the committed copy is clang-formatted.
    # That dirties the working tree after the merge is already committed, and the
    # next invocation would trip the "working tree is dirty" preflight. The
    # committed errors.h is authoritative, so just discard the rebuild's copy.
    git -C "$REPO_ROOT" checkout -- support/ebpf/errors.h 2>/dev/null || true
    return "$rc"
}

# On terminal failure: reset the working branch to the pre-run tip. If we
# created $BRANCH this run, also return to the original ref and delete it;
# in continuing mode we stay on $BRANCH so prior merges are preserved.
abort_to_start() {
    git reset --hard "$ORIGIN_HEAD" >/dev/null 2>&1 || true
    if ! $CONTINUING; then
        git checkout "${ORIGINAL_REF#refs/heads/}" 2>/dev/null || git checkout "$ORIGINAL_REF"
        git branch -D "$BRANCH"
    fi
}

# Reset the branch to ORIGIN_HEAD and merge the given sha (with
# auto-resolve if needed).  Returns 0 on success.  On failure the
# branch is reset back to ORIGIN_HEAD.
merge_from_base() {
    local sha="$1"
    git reset --hard "$ORIGIN_HEAD" >/dev/null 2>&1

    if git -c rerere.enabled=false merge --no-edit "$sha" >/dev/null 2>&1; then
        return 0
    fi

    if [[ -f "$GIT_DIR/MERGE_HEAD" ]] && all_auto_resolvable; then
        if auto_resolve; then
            return 0
        fi
        reset_merge_state
    else
        reset_merge_state
    fi
    git reset --hard "$ORIGIN_HEAD" >/dev/null 2>&1
    return 1
}

# ── preflight ──────────────────────────────────────────────────────────

[[ -z "$(git status --porcelain --untracked-files=no)" ]] || die "Working tree is dirty; commit or stash first"

# rerere records hand-resolved conflicts done between iterations so subsequent
# probes can replay them; autoUpdate stages the replay so all_auto_resolvable
# accepts it instead of bailing on UU-marked files. Script-internal merges
# (probe_merge, merge_from_base) still override with `-c rerere.enabled=false`
# to keep probes deterministic; that overrides these locals for those calls
# only. Set with --local so we don't touch global config.
git config --local rerere.enabled true
git config --local rerere.autoUpdate true

if $DO_FETCH; then
    log "Fetching remotes…"
    git fetch origin
    git fetch upstream
fi

# Save where we came from so we can get back on failure.
ORIGINAL_REF=$(git symbolic-ref --quiet HEAD 2>/dev/null || git rev-parse HEAD)

# Working branch. If it already exists, each invocation continues from its
# tip — that's what makes the iterative "run, hand-resolve one commit, run
# again" loop work without ceremony. --fresh forces a clean restart.
CONTINUING=false
if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
    if $FORCE_FRESH; then
        log "Deleting existing branch $BRANCH (--fresh)"
        if [[ "$(git symbolic-ref --quiet --short HEAD 2>/dev/null)" == "$BRANCH" ]]; then
            git checkout --detach >/dev/null
        fi
        git branch -D "$BRANCH"
        git checkout -b "$BRANCH" "$ORIGIN_REF"
    else
        log "Continuing existing branch $BRANCH"
        git checkout "$BRANCH"
        # Compute remaining upstream commits relative to our progress tip,
        # not the original ORIGIN_REF (which would revisit already-merged
        # commits since they aren't yet in origin/main).
        ORIGIN_REF="$BRANCH"
        CONTINUING=true
    fi
else
    git checkout -b "$BRANCH" "$ORIGIN_REF"
fi
log "Working on branch $BRANCH"

BASE=$(git merge-base "$ORIGIN_REF" "$UPSTREAM_REF")
log "Merge base: $(git log --oneline -1 "$BASE")"

mapfile -t COMMITS < <(git rev-list --reverse "$BASE..$UPSTREAM_REF")
TOTAL=${#COMMITS[@]}
if [[ $TOTAL -eq 0 ]]; then
    log "Already up to date with $UPSTREAM_REF."
    exit 0
fi
log "$TOTAL upstream commit(s) to consider"

ORIGIN_HEAD=$(git rev-parse HEAD)

# Clean-up helper: abort any in-progress merge on unexpected exit.
cleanup() {
    local rc=$?
    if [[ $rc -ne 0 ]] && [[ -f "$GIT_DIR/MERGE_HEAD" ]]; then
        warn "Aborting in-progress merge due to error"
        reset_merge_state
    fi
    return "$rc"
}
trap cleanup EXIT

# ── phase 1: find the furthest conflict-clean commit ──────────────────

LAST_CLEAN=-1

# Optimistic: try the tip first — avoids scanning when everything merges.
if probe_merge "${COMMITS[$((TOTAL - 1))]}"; then
    LAST_CLEAN=$((TOTAL - 1))
    log "Full merge with $UPSTREAM_REF is conflict-clean (or auto-resolvable)"
else
    log "Full merge has non-resolvable conflicts; binary-searching…"
    LAST_CLEAN=$(find_last_clean "$TOTAL")
fi

if [[ $LAST_CLEAN -lt 0 ]]; then
    warn "Even the first upstream commit has non-resolvable conflicts:"
    warn "  $(git log --oneline -1 "${COMMITS[0]}")"
    if $LEAVE_CONFLICTED; then
        log "Attempting merge for manual resolution"
        git -c rerere.enabled=false merge --no-edit "${COMMITS[0]}" >/dev/null 2>&1 || true
        if [[ ! -f "$GIT_DIR/MERGE_HEAD" ]]; then
            warn "Unexpected: merged cleanly"
            exit 0
        fi
        # Apply whatever auto-resolves we can; leave the rest.
        auto_resolve 2>/dev/null || true
        if [[ ! -f "$GIT_DIR/MERGE_HEAD" ]]; then
            log "All conflicts auto-resolved; merge committed"
            exit 0
        fi
        log "Merge of $(git log --oneline -1 "${COMMITS[0]}") left in working tree"
        log "Files still needing manual resolution:"
        unmerged_files | while IFS= read -r f; do log "  $f"; done
        log "When done: git add … && git commit"
        # Prevent the EXIT trap from aborting our intentionally-incomplete merge.
        trap - EXIT
        exit 0
    fi
    if git -c rerere.enabled=false merge --no-commit --no-edit "${COMMITS[0]}" >/dev/null 2>&1; then
        reset_merge_state
    else
        warn "Conflicting files (excluding auto-resolvable):"
        unmerged_files | while IFS= read -r f; do
            is_auto_resolvable_path "$f" && continue
            warn "  $f"
        done
        reset_merge_state
    fi
    abort_to_start
    exit 1
fi

TARGET="${COMMITS[$LAST_CLEAN]}"
log "Furthest conflict-clean commit: $(git log --oneline -1 "$TARGET")"

# ── phase 2: merge the candidate ─────────────────────────────────────

if git -c rerere.enabled=false merge --no-edit "$TARGET"; then
    log "Merged cleanly"
elif [[ -f "$GIT_DIR/MERGE_HEAD" ]]; then
    log "Auto-resolving conflicts…"
    auto_resolve
    log "Auto-resolved and committed"
else
    die "git merge failed unexpectedly"
fi

# ── phase 3: smoke test ──────────────────────────────────────────────

LAST_GOOD=$LAST_CLEAN

if $DO_SMOKE; then
    log "Running smoke tests…"
    if run_smoke; then
        log "Smoke tests passed"
    else
        warn "Smoke tests failed after merging $((LAST_CLEAN + 1)) commit(s)"

        if [[ $LAST_CLEAN -eq 0 ]]; then
            warn "Even the first upstream commit fails smoke; giving up"
            abort_to_start
            exit 1
        fi

        log "Binary-searching for the last commit that passes smoke…"
        lo=0 hi=$((LAST_CLEAN - 1)) smoke_good=-1
        while [[ $lo -le $hi ]]; do
            mid=$(( (lo + hi) / 2 ))
            short=$(git rev-parse --short "${COMMITS[$mid]}")
            log "  smoke-probing $((mid + 1))/$((LAST_CLEAN + 1)) ($short)…"

            if merge_from_base "${COMMITS[$mid]}" && run_smoke; then
                smoke_good=$mid
                lo=$((mid + 1))
            else
                hi=$((mid - 1))
            fi
        done

        if [[ $smoke_good -lt 0 ]]; then
            warn "No upstream commits pass the smoke tests"
            abort_to_start
            exit 1
        fi

        # Land on the winning merge.
        merge_from_base "${COMMITS[$smoke_good]}"
        LAST_GOOD=$smoke_good
        log "Smoke tests pass with $((smoke_good + 1)) commit(s)"

        FIRST_BAD="${COMMITS[$((smoke_good + 1))]}"
        warn "First commit that breaks smoke: $(git log --oneline -1 "$FIRST_BAD")"
    fi
fi

# ── summary ────────────────────────────────────────────────────────────

MERGED=$((LAST_GOOD + 1))
log "Branch $BRANCH: merged $MERGED of $TOTAL upstream commits"
if [[ $MERGED -lt $TOTAL ]]; then
    NEXT="${COMMITS[$((LAST_GOOD + 1))]}"
    warn "Stopped before: $(git log --oneline -1 "$NEXT")"
    warn "$((TOTAL - MERGED)) commit(s) remain and need manual attention"

    if $LEAVE_CONFLICTED; then
        log "Attempting merge of $(git log --oneline -1 "$NEXT") for manual resolution"
        # The merge will fail (we know it can't auto-resolve); proceed regardless.
        git -c rerere.enabled=false merge --no-edit "$NEXT" >/dev/null 2>&1 || true
        if [[ ! -f "$GIT_DIR/MERGE_HEAD" ]]; then
            warn "Unexpected: $NEXT merged cleanly. Nothing left for manual resolution."
            exit 0
        fi
        # Apply whatever auto-resolves apply (BPF blobs, go.mod, metrics).
        # auto_resolve commits on full success; on partial resolution it returns
        # non-zero because `git commit` fails with unmerged paths.
        auto_resolve 2>/dev/null || true
        if [[ ! -f "$GIT_DIR/MERGE_HEAD" ]]; then
            log "All conflicts auto-resolved; merge committed"
            exit 0
        fi
        log "Merge of $(git log --oneline -1 "$NEXT") left in working tree"
        log "Files still needing manual resolution:"
        unmerged_files | while IFS= read -r f; do log "  $f"; done
        log "When done: git add … && git commit"
        # Prevent the EXIT trap from aborting our intentionally-incomplete merge.
        trap - EXIT
        exit 0
    fi

    exit 1
fi
log "Fully merged with $UPSTREAM_REF"
