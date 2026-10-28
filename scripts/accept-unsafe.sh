#!/usr/bin/env bash
# accept a pull request's unsafe-budget violation, from a clone of the repo the
# pull request is in. unsafe counts depend on the platform, so the lock cannot
# be regenerated locally; on a violation the action uploads the runner's lock as
# the `unsafe-budget-lock` artifact. this prints the per-unit change, asks, then
# commits that lock to the pull request's branch and pushes.
#
#   accept-unsafe.sh <pr>
#
# UNSAFE_BUDGET_LOCK_ARTIFACT names the artifact if the action's
# `lock-artifact` input changed it.
set -euo pipefail

name="${UNSAFE_BUDGET_LOCK_ARTIFACT:-unsafe-budget-lock}"

die() {
  echo "accept-unsafe: $*" >&2
  exit 1
}

# `name count` per unit, one line each, sorted by name.
units() {
  awk '
    /^\[\[units\]\]/ { in_unit = 1; next }
    /^\[/ { in_unit = 0 }
    in_unit && /^name = / { gsub(/"/, "", $3); name = $3 }
    in_unit && /^unsafe_count = / { print name, $3 }
  ' "$1" | sort
}

# everything outside the unit counts: tool version, analyzer, scope.
header() {
  sed -n '1,/^\[totals\]/p' "$1"
}

pr="${1:-}"
[ -n "$pr" ] || die "usage: accept-unsafe.sh <pr>"
root="$(git rev-parse --show-toplevel)" || die "run this from a clone of the pull request's repo"
cd "$root"

read -r branch sha cross < <(gh pr view "$pr" \
  --json headRefName,headRefOid,isCrossRepository \
  --jq '"\(.headRefName) \(.headRefOid) \(.isCrossRepository)"')
[ "$cross" = false ] || die "#$pr comes from a fork, its branch cannot be pushed"

run="$(gh api "repos/{owner}/{repo}/actions/artifacts?name=$name&per_page=100" \
  --jq "[.artifacts[] | select(.workflow_run.head_sha == \"$sha\" and (.expired | not))][0].workflow_run.id // empty")"
[ -n "$run" ] || die "no $name artifact for #$pr at ${sha:0:7} (did the check fail?)"

work="$(mktemp -d)"
trap 'git -C "$root" worktree remove --force "$work/tree" 2>/dev/null || true; rm -rf "$work"' EXIT

# off the terminal: gh queries it, and the reply would land in the prompt below.
gh run download "$run" --name "$name" --dir "$work/lock" </dev/null >/dev/null 2>&1 ||
  die "could not download $name from run $run"

lock="$(cat "$work/lock/path")"
case "$lock" in
  unsafe-budget.lock | */unsafe-budget.lock) ;;
  *) die "the artifact names $lock, not an unsafe-budget.lock" ;;
esac
case "/$lock/" in
  */../*) die "the artifact names $lock, outside the repo" ;;
esac

git fetch --quiet origin "$branch"
[ "$(git rev-parse FETCH_HEAD)" = "$sha" ] || die "$branch moved since #$pr's head ${sha:0:7}, rerun ci first"
git worktree add --quiet --detach "$work/tree" "$sha"

old="$work/tree/$lock"
new="$work/lock/unsafe-budget.lock"
[ -f "$old" ] || die "#$pr has no $lock"
diff -q <(header "$old") <(header "$new") >/dev/null ||
  die "the artifact's tool version or scope differs from $lock, update it by hand"

changes="$(join -a1 -a2 -e - -o 0,1.2,2.2 <(units "$old") <(units "$new") | awk '$2 != $3')"
[ -n "$changes" ] || die "the artifact matches $lock, nothing to accept"

echo "#$pr ($branch), $lock:"
echo "$changes" | awk '{ printf "  %-30s %6s -> %s\n", $1, $2, $3 }'
read -r -p "accept? [y/N] " answer </dev/tty
[ "$answer" = y ] || die "not accepted"

cp "$new" "$old"
names="$(echo "$changes" | awk '{ print $1 }' | paste -sd, - | sed 's/,/, /g')"
git -C "$work/tree" commit --quiet -m "chore: accept $names unsafe in unsafe-budget lock" -- "$lock"
git -C "$work/tree" push --quiet origin "HEAD:$branch"
echo "pushed $(git -C "$work/tree" rev-parse --short HEAD) to $branch"
