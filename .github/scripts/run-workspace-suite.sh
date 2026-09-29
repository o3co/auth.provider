#!/usr/bin/env bash
# Runs the current workspace's test suite once: with coverage when the
# workspace wires it (`test:coverage`), plain (`test`) otherwise. CI calls it
# through `pnpm -r exec`, so it runs in each selected workspace's directory.
#
# Once, because CI used to run every package's suite twice — `test`, then
# `test:coverage`, which is the same `vitest run` with `--coverage` — and the
# second pass was about half of the required job's wall time.
#
# The workspace rules in AGENTS.md still hold. A workspace without a `test`
# script fails loudly here (`pnpm run test` refuses a missing script), as the
# root `test` script's missing `--if-present` intends (#88). A package without
# coverage wiring is still tested, just without a report.
set -euo pipefail

if node -e 'const s = require("./package.json").scripts ?? {}; process.exit(s["test:coverage"] ? 0 : 1)'; then
	exec pnpm run test:coverage
fi
exec pnpm run test
