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
 * Bundled module providing all 6 redis-backed user-session stores against
 * the per-purpose ComponentMap slots `userSessionStoreClient`,
 * `sessionRPRegistryClient`, `sessionFamilyIndexClient`,
 * `sessionFederationIndexClient`, `subjectSessionIndexClient` and
 * `subjectRevocationClient` (declared in `@o3co/auth-provider-core`'s
 * `user-sessions/types.mts`). Per A4 §8.1 + §10.1.
 *
 * The last two arrived with #321. #296 shipped `revokeAllForSubject` with
 * in-memory adapters only, so a deployment on this module filled neither
 * subject slot: `verifyJwt` skipped the watermark check, the #376
 * refresh-redemption gate was inert, and a password reset answered
 * `unavailable: ["subjectRevocation", "subjectSessionIndex"]` and revoked
 * nothing — on exactly the deployments that need it, since the in-memory
 * pair is single-process only.
 *
 * `keyPrefix` is the OUTER namespace; the bundled module appends fixed
 * subprefixes per store (`us:` / `rp:` / `fi:` / `fed:` / `sub:` / `rev:`).
 * The two subject stores get their own subprefixes rather than sharing one
 * with the sid-keyed stores: those are keyed by session id and these by
 * subject, and one namespace holding both would let a sid collide with a
 * subject. Consumers that need to override individual subprefixes use the
 * per-adapter constructors with custom keyPrefix values; the bundled module
 * enforces a consistent scheme.
 *
 * Recurring issue class 2: `requires` includes `"config"` because
 * `deps.config` is read in `provides`.
 */
export const redisSessionStoresModule = defineModule({
	name: "redisSessionStores",
	requires: [
		"userSessionStoreClient",
		"sessionRPRegistryClient",
		"sessionFamilyIndexClient",
		"sessionFederationIndexClient",
		"subjectSessionIndexClient",
		"subjectRevocationClient",
		"config",
	] as const,
	configSchema,
	provides: {
		userSessionStore: (deps) => {
			const cfg = (deps.config as unknown as { redisSessionStores: { keyPrefix: string } })
				.redisSessionStores;
			return createRedisUserSessionStore({
				client: deps.userSessionStoreClient,
				keyPrefix: `${cfg.keyPrefix}us:`,
			});
		},
		sessionRPRegistry: (deps) => {
			const cfg = (deps.config as unknown as { redisSessionStores: { keyPrefix: string } })
				.redisSessionStores;
			return createRedisSessionRPRegistry({
				client: deps.sessionRPRegistryClient,
				keyPrefix: `${cfg.keyPrefix}rp:`,
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
