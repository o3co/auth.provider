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

import { z } from "zod";
import { fullSectionsSchema } from "../config/application.schema.mjs";
import { defineModule } from "../modules/index.mjs";
import { createMemoryFederationGrantIntentStore } from "./intentMemory.mjs";
import { createMemoryFederationGrantStore } from "./memory.mjs";

/**
 * Built-in module that provides the in-process
 * {@link FederationGrantIntentStore}: lodged intents, consent challenges and
 * connect transactions.
 *
 * Dev and single-replica only; refused under `core.deployment.mode = "multi"`.
 * Allowed beside a durable grant store on one replica, since a restart loses
 * only flows in progress. Reads no configuration: the flow budget is set by
 * core per intent and the live-intent bound is a port constant.
 */
export const memoryFederationGrantIntentStoreModule = defineModule({
	name: "core-federation-grant-intent-store-memory",
	// What forks per replica, quoted into a refused multi-replica boot.
	replicaSafety: {
		unsafe: true,
		reason:
			"federation grant acquisition forks per replica — an intent lodged on one replica is unknown to every other, so the consent page and the upstream callback answer as if the flow had expired whenever they land elsewhere, and the bound on live intents is counted per replica instead of per (client, subject)",
	},
	provides: {
		federationGrantIntentStore: () => createMemoryFederationGrantIntentStore(),
	},
});

/**
 * Built-in module that provides the in-process memory
 * {@link FederationGrantStore}. Dev and single-replica only — no
 * persistence across restarts, which for a grant means every user connects
 * again, and refused by name under `core.deployment.mode = "multi"`.
 */
export const memoryFederationGrantStoreModule = defineModule({
	name: "core-federation-grant-store-memory",
	// What forks per replica, quoted into a refused multi-replica boot.
	replicaSafety: {
		unsafe: true,
		reason:
			"federation grants fork per replica — a grant lodged or authorized on one replica is unknown to every other, one revoked there still yields upstream tokens here, and a refresh token rotated on one replica leaves every other presenting the old one, which a reuse-detecting IdP answers by revoking the family",
	},
	// Reads the same `federationGrants.tombstoneRetention` (seconds) as the
	// Redis store. Optional: without it the adapter's default applies.
	requires: ["config"] as const,
	// Projected from core's own declaration rather than restated, so this
	// module parses the key exactly as core does (a narrower copy could read
	// `null` as zero and silently keep no tombstones).
	configSchema: z.object({
		federationGrants: fullSectionsSchema.shape.federationGrants,
	}),
	provides: {
		federationGrantStore: (deps) => {
			const seconds = (deps.config as { federationGrants?: { tombstoneRetention?: number } })
				.federationGrants?.tombstoneRetention;
			return createMemoryFederationGrantStore(
				seconds === undefined ? {} : { tombstoneRetentionMs: seconds * 1000 },
			);
		},
	},
});
