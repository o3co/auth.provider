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
 * The lifecycle store admission's tests hand beside a user-session store:
 * core's in-memory one, holding an active record for each session a login
 * opened (a session with no record reads as closed).
 */

import { createInMemorySessionLifecycleStore } from "#/user-sessions/lifecycle/memory.mjs";
import type { SessionLifecycleStore } from "#/user-sessions/lifecycle/types.mjs";

/**
 * An in-memory lifecycle store holding an active record for each `[sid, sub]`
 * (`sid-1` for `user-1` by default), ending a day from its creation, opened
 * before any member answers.
 */
export function openedLifecycleStore(
	...sessions: readonly (readonly [sid: string, sub: string])[]
): SessionLifecycleStore {
	const store = createInMemorySessionLifecycleStore();
	const held = sessions.length === 0 ? [["sid-1", "user-1"] as const] : sessions;
	const end = new Date(Date.now() + 86_400_000);
	const opened = (async () => {
		for (const [sid, sub] of held) await store.open(sid, sub, end);
	})();
	const after =
		<A extends unknown[], R>(call: (...args: A) => Promise<R>) =>
		async (...args: A): Promise<R> => {
			await opened;
			return call(...args);
		};
	return {
		kind: store.kind,
		open: after(store.open.bind(store)),
		join: after(store.join.bind(store)),
		beginClose: after(store.beginClose.bind(store)),
		completeIf: after(store.completeIf.bind(store)),
		read: after(store.read.bind(store)),
		listClosing: after(store.listClosing.bind(store)),
	};
}
