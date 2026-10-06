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

/**
 * Core's session lifecycle for a test that wires a user-session store, which
 * the session package's routes and modules then require beside it: a fake
 * whose every member is a spy answering as an always-available lifecycle
 * does, and a module that fills the slot with one.
 */

import { defineModule, type Module, type SessionLifecycle } from "@o3co/auth-provider-core";
import { vi } from "vitest";

/**
 * A session lifecycle whose answers a test may set, every member a spy:
 * `open` answers `opened`, `join` `joined`, `close` `done` with nothing
 * joined, `liveness` `not_live`, `federations` none, `resumePending` nothing.
 */
export function fakeSessionLifecycle(over: Partial<SessionLifecycle> = {}) {
	return {
		open: vi.fn<SessionLifecycle["open"]>(over.open ?? (async () => ({ outcome: "opened" }))),
		join: vi.fn<SessionLifecycle["join"]>(over.join ?? (async () => ({ outcome: "joined" }))),
		close: vi.fn<SessionLifecycle["close"]>(
			over.close ?? (async () => ({ outcome: "done", rps: [], federations: [] })),
		),
		liveness: vi.fn<SessionLifecycle["liveness"]>(
			over.liveness ?? (async () => ({ outcome: "not_live" })),
		),
		federations: vi.fn<SessionLifecycle["federations"]>(
			over.federations ?? (async () => ({ outcome: "listed", federations: [] })),
		),
		resumePending: vi.fn<SessionLifecycle["resumePending"]>(
			over.resumePending ?? (async () => ({ done: 0, pending: 0, unavailable: 0 })),
		),
	} satisfies SessionLifecycle;
}

/** Fills the `sessionLifecycle` slot with `lifecycle`, a fresh fake by default. */
export const sessionLifecycleTestModule = (
	lifecycle: SessionLifecycle = fakeSessionLifecycle(),
): Module =>
	defineModule({
		name: "test:session-lifecycle",
		provides: { sessionLifecycle: () => lifecycle },
	});
