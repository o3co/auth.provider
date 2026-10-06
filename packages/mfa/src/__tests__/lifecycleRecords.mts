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
 * The lifecycle store admission reads beside a user-session store, for the
 * requirement tests that call admission directly.
 */

import {
	createInMemorySessionLifecycleStore,
	type SessionLifecycleStore,
} from "@o3co/auth-provider-core";

/**
 * Core's in-memory lifecycle store, holding an active record for every
 * session of `sub` admission asks about, as the login that established it
 * opened one (a session with no record reads as closed).
 */
export function openingLifecycleStore(sub: string): SessionLifecycleStore {
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
