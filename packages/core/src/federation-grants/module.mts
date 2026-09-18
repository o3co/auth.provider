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
import { defineModule } from "../modules/index.mjs";
import { createMemoryFederationGrantStore } from "./memory.mjs";

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
	configSchema: z.object({
		federationGrants: z
			.object({ tombstoneRetention: z.coerce.number().int().nonnegative().optional() })
			.default({}),
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
