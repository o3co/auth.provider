#!/usr/bin/env bash
# Every commit a PR brings, not only its head, must be a tree that installs.
#
# 2a2e2059 (the vitest 5 upgrade) landed through a rebase merge carrying
# literal conflict markers in create-app/package.json. The PR's head was
# fine — a later commit repaired it — so CI, which builds the head, passed;
# but `pnpm install` cannot run at that commit, and `git bisect` across the
# release range stops there (v0.13.0 audit).
#
# For each commit in BASE..HEAD, the files that commit adds, modifies, copies,
# renames or retypes — against every parent, for a merge — must carry no
# conflict-marker line, and any package.json among them must parse. The head
# tree is then checked whole: every package.json, every tracked text file.
#
# Fails closed: a range that does not resolve, or a git command that errors,
# is a failure, never an empty scan reported as clean.
#
# Usage: check-commit-integrity.sh <base> <head>
set -euo pipefail

base="${1:?usage: check-commit-integrity.sh <base> <head>}"
head="${2:?usage: check-commit-integrity.sh <base> <head>}"

for rev in "$base" "$head"; do
	if ! git rev-parse --verify --quiet "${rev}^{commit}" >/dev/null; then
		echo "::error::${rev} is not a commit in this checkout — is the history fetched?"
		exit 2
	fi
done

# A line that opens or closes a conflict hunk. `=======` alone is left out:
# it is also a legitimate line in Markdown and generated text.
MARKER='^(<<<<<<<|>>>>>>>)( |$)'

failures=0

# Print conflict-marker lines in <rev> [-- <paths>...]; status 0 when there are
# some, 1 when there are none. Any other `git grep` status is an error, and
# stops the script rather than reading as "none".
markers_in() {
	local out status
	set +e
	out="$(git grep -I -nE "$MARKER" "$@")"
	status=$?
	set -e
	case "$status" in
	0) printf '%s\n' "$out" ;;
	1) return 1 ;;
	*)
		echo "::error::git grep failed (status ${status}) scanning $1"
		exit 2
		;;
	esac
}

parses() { # <rev>:<path>
	local json
	json="$(git show "$1")" || return 1
	printf '%s' "$json" | node -e 'JSON.parse(require("node:fs").readFileSync(0, "utf8"))' 2>/dev/null
}

commits="$(git rev-list --reverse "$base..$head")"

for commit in $commits; do
	subject="$(git log -1 --format='%h %s' "$commit")"
	# `-m` diffs a merge against each parent; `d` drops deletions only, keeping
	# copies and type changes. A read loop rather than `mapfile`, so the script
	# also runs under the bash 3.2 macOS ships.
	listing="$(git diff-tree -m --no-commit-id --name-only -r --diff-filter=d "$commit")"
	changed=()
	while IFS= read -r path; do
		[ -n "$path" ] && changed+=("$path")
	done < <(printf '%s\n' "$listing" | sort -u)
	[ "${#changed[@]}" -eq 0 ] && continue

	if found="$(markers_in "$commit" -- "${changed[@]}")"; then
		echo "::error::conflict markers in ${subject}:"
		echo "$found"
		failures=$((failures + 1))
	fi
	for path in "${changed[@]}"; do
		case "$path" in
		package.json | */package.json)
			if ! parses "$commit:$path"; then
				echo "::error::${path} is not valid JSON in ${subject}"
				failures=$((failures + 1))
			fi
			;;
		esac
	done
done

if found="$(markers_in "$head")"; then
	echo "::error::conflict markers in the head tree:"
	echo "$found"
	failures=$((failures + 1))
fi
tree="$(git ls-tree -r --name-only "$head")"
while IFS= read -r path; do
	[ -z "$path" ] && continue
	if ! parses "$head:$path"; then
		echo "::error::${path} is not valid JSON at the head"
		failures=$((failures + 1))
	fi
done < <(printf '%s\n' "$tree" | grep -E '(^|/)package\.json$' || true)

if [ "$failures" -gt 0 ]; then
	echo "commit integrity: ${failures} problem(s)"
	exit 1
fi
echo "OK: every commit in ${base}..${head} carries parseable package.json files and no conflict markers"
