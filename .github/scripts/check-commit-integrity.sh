#!/usr/bin/env bash
# Every commit a PR brings, not only its head, must be a tree that installs.
#
# 2a2e2059 (the vitest 5 upgrade) landed through a rebase merge carrying
# literal conflict markers in create-app/package.json. The PR's head was
# fine — a later commit repaired it — so CI, which builds the head, passed;
# but `pnpm install` cannot run at that commit, and `git bisect` across the
# release range stops there (v0.13.0 audit).
#
# For each commit in BASE..HEAD, the files that commit adds or modifies must
# carry no conflict-marker line, and any package.json among them must parse.
# The head tree is then checked whole: every package.json, every tracked text
# file.
#
# Usage: check-commit-integrity.sh <base> <head>
set -euo pipefail

base="${1:?usage: check-commit-integrity.sh <base> <head>}"
head="${2:?usage: check-commit-integrity.sh <base> <head>}"

# A line that opens or closes a conflict hunk. `=======` alone is left out:
# it is also a legitimate line in Markdown and generated text.
MARKER='^(<<<<<<<|>>>>>>>)( |$)'

failures=0

parses() { # <rev>:<path>
	git show "$1" | node -e 'JSON.parse(require("node:fs").readFileSync(0, "utf8"))' 2>/dev/null
}

for commit in $(git rev-list --reverse "$base..$head"); do
	subject="$(git log -1 --format='%h %s' "$commit")"
	# A read loop rather than `mapfile`, so the script also runs under the bash
	# 3.2 macOS ships.
	changed=()
	while IFS= read -r path; do changed+=("$path"); done \
		< <(git diff-tree --no-commit-id --name-only -r --diff-filter=AMR "$commit")
	[ "${#changed[@]}" -eq 0 ] && continue

	if markers="$(git grep -I -nE "$MARKER" "$commit" -- "${changed[@]}")"; then
		echo "::error::conflict markers in ${subject}:"
		echo "$markers"
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

if markers="$(git grep -I -nE "$MARKER" "$head")"; then
	echo "::error::conflict markers in the head tree:"
	echo "$markers"
	failures=$((failures + 1))
fi
while IFS= read -r path; do
	if ! parses "$head:$path"; then
		echo "::error::${path} is not valid JSON at the head"
		failures=$((failures + 1))
	fi
done < <(git ls-tree -r --name-only "$head" | grep -E '(^|/)package\.json$')

if [ "$failures" -gt 0 ]; then
	echo "commit integrity: ${failures} problem(s)"
	exit 1
fi
echo "OK: every commit in ${base}..${head} carries parseable package.json files and no conflict markers"
