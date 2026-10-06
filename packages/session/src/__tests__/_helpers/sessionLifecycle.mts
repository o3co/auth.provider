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
 * does, and a module that fills the slot with one; and the lifecycle store
 * admission reads beside a user-session store.
 */

import {
	createInMemorySessionLifecycleStore,
	defineModule,
	type Module,
	type SessionLifecycle,
	type SessionLifecycleStore,
} from "@o3co/auth-provider-core";
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

/**
 * Fills the `sessionLifecycle` slot with `lifecycle`, a fresh fake by default,
 * and the `sessionLifecycleStore` slot with `store`, one holding an active
 * record for every session admission asks about by default.
 */
export const sessionLifecycleTestModule = (
	lifecycle: SessionLifecycle = fakeSessionLifecycle(),
	store: SessionLifecycleStore = openingLifecycleStore(),
): Module =>
	defineModule({
		name: "test:session-lifecycle",
		provides: { sessionLifecycle: () => lifecycle, sessionLifecycleStore: () => store },
	});

/**
 * Core's in-memory lifecycle store, holding an active record for every
 * session of `sub` admission asks about, as the login that established it
 * opened one (a session with no record reads as closed). A record a close
 * moved on stays as it is.
 */
export function openingLifecycleStore(sub = "user-1"): SessionLifecycleStore {
	const store = createInMemorySessionLifecycleStore();
	const end = new Date(Date.now() + 86_400_000);
	return {
		...store,
		read: async (sid) => {
			await store.open(sid, sub, end);
			return store.read(sid);
		},
	};
}
