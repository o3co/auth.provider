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
 * {@link FederationGrantIntentStore} (#593, D16, slice 6) — acquisition's
 * records: the intent a backend lodged, the consent challenge a browser
 * answers, and the connect transaction a callback consumes.
 *
 * Dev and single-replica only, and refused by name under
 * `deployment.mode = "multi"`. Unlike the in-memory grant store beside a
 * durable one, this pairing is permitted for a single replica: a restart loses
 * flows in progress, and no established grant or revocation with it.
 *
 * It needs no configuration. The one deadline of an acquisition is the flow
 * budget, which core sets when it lodges the intent, and the bound on live
 * first-time intents is a constant on the port — neither is an operator's to
 * tune, so this module reads nothing.
 */
export const memoryFederationGrantIntentStoreModule = defineModule({
	name: "core-federation-grant-intent-store-memory",
	// #455: what forks per replica, quoted into a refused multi-replica boot.
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
 * {@link FederationGrantStore} (#593). Dev and single-replica only — no
 * persistence across restarts, which for a grant means every user connects
 * again, and refused by name under `deployment.mode = "multi"`.
 */
export const memoryFederationGrantStoreModule = defineModule({
	name: "core-federation-grant-store-memory",
	// #455: what forks per replica, quoted into a refused multi-replica boot.
	replicaSafety: {
		unsafe: true,
		reason:
			"federation grants fork per replica — a grant lodged or authorized on one replica is unknown to every other, one revoked there still yields upstream tokens here, and a refresh token rotated on one replica leaves every other presenting the old one, which a reuse-detecting IdP answers by revoking the family",
	},
	// #593 slice 4: the same `federationGrants.tombstoneRetention` the Redis
	// store reads, in the same seconds — a deployment that shortens it must not
	// find the in-memory adapter still keeping thirty days of tombstones. The
	// key is optional and the adapter's own default applies without it, so this
	// module needs no configuration to be installed.
	requires: ["config"] as const,
	// Projected from core's own declaration rather than restated: a narrower
	// copy here read `tombstoneRetention: null` as zero — Copilot's finding —
	// and silently gave a deployment no tombstones at all, which is the one
	// setting where "no tombstones" and "thirty days" look identical until
	// somebody asks why a revoked grant cannot be looked up.
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
