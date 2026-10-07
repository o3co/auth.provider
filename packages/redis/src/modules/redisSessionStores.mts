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

import { defineModule } from "@o3co/auth-provider-core";
import { keyPrefixSection, redisReference } from "../internal/section.mjs";
import { createRedisSessionLifecycleStore } from "../session-lifecycle-store.mjs";
import { createRedisSubjectRevocation } from "../subjectRevocation.mjs";
import { createRedisSubjectSessionIndex } from "../subjectSessionIndex.mjs";
import { createRedisUserSessionStore } from "../userSessionStore.mjs";

/**
 * Bundled module providing the Redis session record store, the two subject
 * stores and the session lifecycle store off the per-purpose ComponentMap
 * slots `userSessionStoreClient`, `subjectSessionIndexClient`,
 * `subjectRevocationClient` and `sessionLifecycleStoreClient` (this
 * package's `clients.mts`).
 *
 * The subject stores (`subjectSessionIndex`, `subjectRevocation`) carry
 * subject-level revocation across replicas. Without them `verifyJwt` skips the
 * subject watermark, so the refresh grant's watermark check does nothing, and
 * a password reset's `revokeAllForSubject` reports both `unavailable` and ends
 * no session or access token.
 *
 * `keyPrefix` is the outer namespace; each store gets a fixed subprefix
 * (`us:` / `sub:` / `rev:` / `lc:`). The subject-keyed stores do not share one
 * with the sid-keyed stores, so a sid cannot collide with a subject. To
 * override a single subprefix, use the per-adapter constructors.
 *
 * `keyPrefix` is its own section's, `redis-session-stores` (strict);
 * `redisSessionStores`, the section's old path, refuses boot naming it. The
 * optional `logger` goes to the user-session store, which reports a stored
 * record it cannot read (`user_session_corrupt_envelope`), and to the
 * revocation store, which says a clamped boundary
 * (`subject_revocation_boundary_clamped`); `consoleLogger` when it is empty.
 *
 * The lifecycle store is built by `createRedisSessionLifecycleStore`, so a
 * server that fails the eviction gate (`internal/eviction-policy.mts`)
 * refuses the boot with a `RedisStoreEvictableError`.
 */
export const redisSessionStoresModule = defineModule({
	name: "redis-session-stores",
	requires: [
		"userSessionStoreClient",
		"subjectSessionIndexClient",
		"subjectRevocationClient",
		"sessionLifecycleStoreClient",
	] as const,
	optional: ["logger"] as const,
	section: {
		schema: keyPrefixSection,
		reference: redisReference(),
		relocatedFrom: {
			redisSessionStores: { to: "", environmentVariable: null },
			"redisSessionStores.keyPrefix": "keyPrefix",
		},
	},
	provides: {
		userSessionStore: (deps) => {
			return createRedisUserSessionStore({
				client: deps.userSessionStoreClient,
				keyPrefix: `${deps.section.keyPrefix}us:`,
				...(deps.logger !== undefined ? { logger: deps.logger } : {}),
			});
		},
		subjectSessionIndex: (deps) => {
			return createRedisSubjectSessionIndex({
				client: deps.subjectSessionIndexClient,
				keyPrefix: `${deps.section.keyPrefix}sub:`,
			});
		},
		subjectRevocation: (deps) => {
			return createRedisSubjectRevocation({
				client: deps.subjectRevocationClient,
				keyPrefix: `${deps.section.keyPrefix}rev:`,
				...(deps.logger !== undefined ? { logger: deps.logger } : {}),
			});
		},
		sessionLifecycleStore: (deps) =>
			createRedisSessionLifecycleStore({
				client: deps.sessionLifecycleStoreClient,
				keyPrefix: `${deps.section.keyPrefix}lc:`,
			}),
	},
});
