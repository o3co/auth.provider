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
import { z } from "zod";
import { createRedisSessionFamilyIndex } from "../sessionFamilyIndex.mjs";
import { createRedisSessionFederationIndex } from "../sessionFederationIndex.mjs";
import { createRedisSessionRPRegistry } from "../sessionRPRegistry.mjs";
import { createRedisSubjectRevocation } from "../subjectRevocation.mjs";
import { createRedisSubjectSessionIndex } from "../subjectSessionIndex.mjs";
import { createRedisUserSessionStore } from "../userSessionStore.mjs";

const configSchema = z.object({
	redisSessionStores: z
		.object({
			keyPrefix: z.string().default("ss:"),
		})
		.default({ keyPrefix: "ss:" }),
});

/**
 * Bundled module providing the six Redis user-session stores off the
 * per-purpose ComponentMap slots `userSessionStoreClient`,
 * `sessionRPRegistryClient`, `sessionFamilyIndexClient`,
 * `sessionFederationIndexClient`, `subjectSessionIndexClient` and
 * `subjectRevocationClient` (declared in `@o3co/auth-provider-core`'s
 * `user-sessions/types.mts`).
 *
 * The subject stores (`subjectSessionIndex`, `subjectRevocation`) carry
 * subject-level revocation across replicas. Without them `verifyJwt` skips the
 * subject watermark, so the refresh grant's watermark check does nothing, and
 * a password reset's `revokeAllForSubject` reports both `unavailable` and ends
 * no session or access token.
 *
 * `keyPrefix` is the outer namespace; each store gets a fixed subprefix
 * (`us:` / `rp:` / `fi:` / `fed:` / `sub:` / `rev:`). The subject-keyed stores
 * do not share one with the sid-keyed stores, so a sid cannot collide with a
 * subject. To override a single subprefix, use the per-adapter constructors.
 *
 * `requires` includes `"config"` because `provides` reads `deps.config`. The
 * optional `logger` goes to the two stores that report a stored record they
 * cannot read, the user-session store (`user_session_corrupt_envelope`) and
 * the RP registry (`session_rp_registry_corrupt_envelope`); `consoleLogger`
 * when it is empty.
 */
export const redisSessionStoresModule = defineModule({
	name: "redis-session-stores",
	requires: [
		"userSessionStoreClient",
		"sessionRPRegistryClient",
		"sessionFamilyIndexClient",
		"sessionFederationIndexClient",
		"subjectSessionIndexClient",
		"subjectRevocationClient",
		"config",
	] as const,
	optional: ["logger"] as const,
	configSchema,
	provides: {
		userSessionStore: (deps) => {
			const cfg = (deps.config as unknown as { redisSessionStores: { keyPrefix: string } })
				.redisSessionStores;
			return createRedisUserSessionStore({
				client: deps.userSessionStoreClient,
				keyPrefix: `${cfg.keyPrefix}us:`,
				...(deps.logger !== undefined ? { logger: deps.logger } : {}),
			});
		},
		sessionRPRegistry: (deps) => {
			const cfg = (deps.config as unknown as { redisSessionStores: { keyPrefix: string } })
				.redisSessionStores;
			return createRedisSessionRPRegistry({
				client: deps.sessionRPRegistryClient,
				keyPrefix: `${cfg.keyPrefix}rp:`,
				...(deps.logger !== undefined ? { logger: deps.logger } : {}),
			});
		},
		sessionFamilyIndex: (deps) => {
			const cfg = (deps.config as unknown as { redisSessionStores: { keyPrefix: string } })
				.redisSessionStores;
			return createRedisSessionFamilyIndex({
				client: deps.sessionFamilyIndexClient,
				keyPrefix: `${cfg.keyPrefix}fi:`,
			});
		},
		sessionFederationIndex: (deps) => {
			const cfg = (deps.config as unknown as { redisSessionStores: { keyPrefix: string } })
				.redisSessionStores;
			return createRedisSessionFederationIndex({
				client: deps.sessionFederationIndexClient,
				keyPrefix: `${cfg.keyPrefix}fed:`,
			});
		},
		subjectSessionIndex: (deps) => {
			const cfg = (deps.config as unknown as { redisSessionStores: { keyPrefix: string } })
				.redisSessionStores;
			return createRedisSubjectSessionIndex({
				client: deps.subjectSessionIndexClient,
				keyPrefix: `${cfg.keyPrefix}sub:`,
			});
		},
		subjectRevocation: (deps) => {
			const cfg = (deps.config as unknown as { redisSessionStores: { keyPrefix: string } })
				.redisSessionStores;
			return createRedisSubjectRevocation({
				client: deps.subjectRevocationClient,
				keyPrefix: `${cfg.keyPrefix}rev:`,
			});
		},
	},
});
