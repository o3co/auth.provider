/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { fileURLToPath } from "node:url";

/**
 * The workspace-wide test deadline policy (#357) — one floor, one reason.
 *
 * `pnpm -r run test` runs up to four workspaces' vitest processes at once
 * (pnpm's default `--workspace-concurrency`), each with its own worker pool,
 * and `packages/redis` boots a Redis testcontainer per test file. On a
 * saturated box the transform+import of a test file can exceed vitest's 5s
 * default all by itself, and a test then fails with "Test timed out" on
 * nothing more than an `await import(...)` — a machine-load artifact reported
 * as a product failure, landing on whichever package lost the race that run.
 *
 * The floor is uniform because the load is workspace-global: any package can
 * be the one starved, so per-package numbers chosen ad hoc ("some at 5s, some
 * at 20s, for reasons no one wrote down" — #357) only decide who flakes next.
 * Raising the deadline does not hide a real hang: a genuinely stuck test
 * still fails, 15 seconds later.
 *
 * A package with a documented slower fixture may RAISE this floor by placing
 * its own literals after the spread (`packages/redis` does, 30s, for
 * container boot), never lower it. `templates/standalone/vitest.config.mts`
 * repeats these values as literals instead of importing this file — the
 * template is copied verbatim into scaffolded projects, where this file does
 * not exist — and its comment points back here.
 */
export const WORKSPACE_TEST_TIMEOUTS = {
	testTimeout: 20_000,
	hookTimeout: 20_000,
} as const;

/**
 * Setup files every package's vitest run loads (#556).
 *
 * `vitest.supertest-loopback.mts` binds the server supertest starts to
 * `127.0.0.1`, the address supertest dials — unpatched, macOS can hand that
 * server a port another process holds on `127.0.0.1`, and the request hangs on
 * the other process until the test timeout. The file is a no-op in a package
 * that has no supertest, so it is wired into all of them: a package that adds
 * supertest later is covered without anyone remembering to. A package config
 * that sets its own `setupFiles` must keep these in the list.
 *
 * The path is absolute because vitest resolves `setupFiles` against each
 * package's root. `templates/standalone` cannot import this file (see above),
 * so its `request(app)` calls are not covered by it; the servers its tests
 * start by hand bind `127.0.0.1` explicitly.
 */
export const WORKSPACE_TEST_SETUP: { readonly setupFiles: string[] } = {
	setupFiles: [fileURLToPath(new URL("./vitest.supertest-loopback.mts", import.meta.url))],
};
