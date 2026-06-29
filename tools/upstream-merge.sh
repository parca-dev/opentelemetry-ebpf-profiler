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
#   * go.mod / go.sum — accept upstream, then `go mod tidy`
#
# Everything else is considered a "real" conflict and the script stops
# before it, leaving you with the largest clean merge possible.
#
# Usage:
#   tools/upstream-merge.sh [options] [upstream-ref] [origin-ref]
#
# Options:
#   --no-fetch   Skip 'git fetch' (useful when you already fetched)
#   --no-smoke   Skip the post-merge smoke test
#   -h, --help   Show this help
#
# Defaults: upstream/main and origin/main.

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

args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-fetch)  DO_FETCH=false; shift ;;
        --no-smoke)  DO_SMOKE=false; shift ;;
        -h|--help)   sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)           args+=("$1"); shift ;;
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

# Print paths of unmerged (conflicting) files, one per line.
unmerged_files() {
    git diff --name-only --diff-filter=U
}

# Return 0 if every conflicting file is one we know how to auto-resolve.
all_auto_resolvable() {
    local f count=0
    while IFS= read -r f; do
        [[ "$f" =~ $BPF_BLOB_RE || "$f" =~ $GOMOD_RE ]] || return 1
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
    if git merge --no-commit --no-edit "$sha" >/dev/null 2>&1; then
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

# Resolve auto-resolvable conflicts in the working tree and commit.
# Uses explicit || return 1 so this is safe to call from condition
# contexts (e.g. inside an `if`) where set -e is suppressed.
auto_resolve() {
    local has_bpf=false has_gomod=false f
    local -a conflicts
    mapfile -t conflicts < <(unmerged_files)

    for f in "${conflicts[@]}"; do
        case "$f" in
            support/ebpf/tracer.ebpf.*) has_bpf=true  ;;
            go.mod|go.sum)              has_gomod=true ;;
        esac
    done

    # ── go.mod / go.sum ────────────────────────────────────────────────
    if $has_gomod; then
        log "  go.mod/go.sum → accept upstream + go mod tidy"
        git checkout --theirs -- go.mod                              || return 1
        git checkout --theirs -- go.sum 2>/dev/null || true
        ( cd "$REPO_ROOT" && go mod tidy )                           || return 1
        git add go.mod go.sum                                        || return 1
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

    # Annotate the merge commit message.
    local merge_msg="$GIT_DIR/MERGE_MSG"
    if [[ -f "$merge_msg" ]]; then
        {
            cat "$merge_msg"
            echo ""
            echo "Auto-resolved:"
            if $has_gomod; then echo "  - go.mod/go.sum: accepted upstream, ran go mod tidy"; fi
            if $has_bpf;   then echo "  - BPF blobs: rebuilt from merged C sources"; fi
        } > "${merge_msg}.tmp"
        mv "${merge_msg}.tmp" "$merge_msg"
    fi

    git commit --no-edit                                             || return 1
}

# Run every command in SMOKE_CMDS.  Returns 0 only if all pass.
run_smoke() {
    local cmd
    for cmd in "${SMOKE_CMDS[@]}"; do
        log "  smoke: $cmd"
        if ! ( cd "$REPO_ROOT" && eval "$cmd" ); then
            return 1
        fi
    done
}

# Reset the branch to ORIGIN_HEAD and merge the given sha (with
# auto-resolve if needed).  Returns 0 on success.  On failure the
# branch is reset back to ORIGIN_HEAD.
merge_from_base() {
    local sha="$1"
    git reset --hard "$ORIGIN_HEAD" >/dev/null 2>&1

    if git merge --no-edit "$sha" >/dev/null 2>&1; then
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

# rerere makes this script meaningfully better: when we resolve a conflict by
# hand and rerun, the next probe replays that resolution. autoUpdate is what
# stages it — without it the file shows up as UU and all_auto_resolvable
# rejects the whole batch, so the script bails on conflicts it could have
# carried through. Set both with --local so we don't touch global config.
git config --local rerere.enabled true
git config --local rerere.autoUpdate true

if $DO_FETCH; then
    log "Fetching remotes…"
    git fetch origin
    git fetch upstream
fi

BASE=$(git merge-base "$ORIGIN_REF" "$UPSTREAM_REF")
log "Merge base: $(git log --oneline -1 "$BASE")"

mapfile -t COMMITS < <(git rev-list --reverse "$BASE..$UPSTREAM_REF")
TOTAL=${#COMMITS[@]}
if [[ $TOTAL -eq 0 ]]; then
    log "Already up to date with $UPSTREAM_REF."
    exit 0
fi
log "$TOTAL upstream commit(s) to consider"

# Save where we came from so we can get back on failure.
ORIGINAL_REF=$(git symbolic-ref --quiet HEAD 2>/dev/null || git rev-parse HEAD)

# Create a working branch rooted at origin/main.
BRANCH="upstream-merge"
git checkout -b "$BRANCH" "$ORIGIN_REF"
log "Working on branch $BRANCH"

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
    if git merge --no-commit --no-edit "${COMMITS[0]}" >/dev/null 2>&1; then
        reset_merge_state
    else
        warn "Conflicting files:"
        unmerged_files | while IFS= read -r f; do
            [[ "$f" =~ $BPF_BLOB_RE || "$f" =~ $GOMOD_RE ]] && continue
            warn "  $f"
        done
        reset_merge_state
    fi
    git checkout "${ORIGINAL_REF#refs/heads/}" 2>/dev/null || git checkout "$ORIGINAL_REF"
    git branch -D "$BRANCH"
    exit 1
fi

TARGET="${COMMITS[$LAST_CLEAN]}"
log "Furthest conflict-clean commit: $(git log --oneline -1 "$TARGET")"

# ── phase 2: merge the candidate ─────────────────────────────────────

if git merge --no-edit "$TARGET"; then
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
            git reset --hard "$ORIGIN_HEAD" >/dev/null 2>&1
            git checkout "${ORIGINAL_REF#refs/heads/}" 2>/dev/null || git checkout "$ORIGINAL_REF"
            git branch -D "$BRANCH"
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
            git reset --hard "$ORIGIN_HEAD" >/dev/null 2>&1
            git checkout "${ORIGINAL_REF#refs/heads/}" 2>/dev/null || git checkout "$ORIGINAL_REF"
            git branch -D "$BRANCH"
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
    exit 1
fi
log "Fully merged with $UPSTREAM_REF"
