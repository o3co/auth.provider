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
 * The federation token store's boot check of its server's eviction policy.
 * `attach` and the conditional writes answer a resent copy from a replay key
 * that lives about 2 s, and `attach` has no generation check behind it: a
 * policy that may evict that key lets a resent `attach` write again, putting
 * an older record back over a later write, or a removed record (its refresh
 * token included) back after a logout. So every eviction policy refuses the
 * boot. A policy that could not be read, one the check does not know, or a
 * server that could not answer is one info line, and the boot goes on.
 */

import { type Logger, loggableError } from "@o3co/auth-provider-core";
import type { RedisDurability } from "../clients.mjs";
import {
	ALLKEYS_POLICIES,
	RedisStoreEvictableError,
	VOLATILE_POLICIES,
} from "./eviction-policy.mjs";

const STORE = { store: "federation-tokens", adapter: "redis" } as const;

/**
 * Reads the policy once through `durability`: throws a
 * {@link RedisStoreEvictableError} for an eviction policy, else writes at most
 * one info line on `logger`.
 */
export async function checkFederationTokenEviction(
	durability: () => Promise<RedisDurability>,
	logger: Logger,
): Promise<void> {
	let report: RedisDurability;
	try {
		report = await durability();
	} catch (err) {
		logger.info({ ...STORE, err: loggableError(err) }, "federation_token_store_eviction_unchecked");
		return;
	}
	const policy = report.maxmemoryPolicy;
	if (policy === "noeviction") return;
	if (policy !== undefined && (VOLATILE_POLICIES.has(policy) || ALLKEYS_POLICIES.has(policy))) {
		throw new RedisStoreEvictableError("federationTokenStore", policy, {
			reason: "federation-token-store-evictable",
			evicts: "a resent write's replay key",
			holds:
				"a resent attach would then write again, putting an older record back over a later write, or a logged-out session's upstream tokens back",
			remedy: '"noeviction"',
		});
	}
	logger.info(
		{
			...STORE,
			...(policy === undefined ? {} : { maxmemoryPolicy: policy }),
			...(report.refusal === undefined ? {} : { err: loggableError(report.refusal) }),
		},
		"federation_token_store_eviction_unchecked",
	);
}
