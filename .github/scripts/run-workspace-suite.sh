#!/usr/bin/env bash
# Runs the current workspace's test suite once: with coverage when the
# workspace wires it (`test:coverage`), plain (`test`) otherwise. CI calls it
# through `pnpm -r exec`, so it runs in each selected workspace's directory.
#
# Once, because CI used to run every package's suite twice — `test`, then
# `test:coverage`, which is the same `vitest run` with `--coverage` — and the
# second pass was about half of the required job's wall time.
#
# The workspace rules in AGENTS.md hold here. Every workspace must define
# `test` (#88): one that does not fails, even when it defines `test:coverage`,
# before anything runs. pnpm's recursive `run` would skip it silently. A
# package without coverage wiring is still tested, just without a report.
set -euo pipefail

if ! script="$(node -e '
	const s = require("./package.json").scripts ?? {};
	if (!s.test) process.exit(3);
	process.stdout.write(s["test:coverage"] ? "test:coverage" : "test");
')"; then
	echo "::error::$PWD defines no \"test\" script; every workspace must (AGENTS.md, #88)" >&2
	exit 1
fi
exec pnpm run "$script"
