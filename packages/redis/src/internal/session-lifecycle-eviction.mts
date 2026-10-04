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
 * The session lifecycle store's boot check of its server's eviction policy.
 * Every key the store writes must stay until it expires: an evicted record
 * lets a closed session be opened and joined again, or loses a close's
 * pending work; an evicted replay key lets a resent write apply again; and
 * the closing index carries no TTL, so an evicted index hides a closing
 * record from the listing. So every eviction policy refuses the boot. A
 * policy that could not be read, one the check does not know, or a server
 * that could not answer is one warning, and the boot goes on.
 */

import { type Logger, loggableError } from "@o3co/auth-provider-core";
import type { RedisDurability } from "../clients.mjs";
import {
	ALLKEYS_POLICIES,
	RedisStoreEvictableError,
	VOLATILE_POLICIES,
} from "./eviction-policy.mjs";

const STORE = { store: "sessionLifecycleStore", adapter: "redis" } as const;

/**
 * Reads the policy once through `durability`: throws a
 * {@link RedisStoreEvictableError} for an eviction policy, else writes at most
 * one warning on `logger`.
 */
export async function checkSessionLifecycleEviction(
	durability: () => Promise<RedisDurability>,
	logger: Logger,
): Promise<void> {
	let report: RedisDurability;
	try {
		report = await durability();
	} catch (err) {
		logger.warn(
			{ ...STORE, err: loggableError(err) },
			"session_lifecycle_store_eviction_unchecked",
		);
		return;
	}
	const policy = report.maxmemoryPolicy;
	if (policy === "noeviction") return;
	if (policy !== undefined && (VOLATILE_POLICIES.has(policy) || ALLKEYS_POLICIES.has(policy))) {
		throw new RedisStoreEvictableError("sessionLifecycleStore", policy, {
			reason: "session-lifecycle-store-evictable",
			evicts: "a session's record, a write's replay key or the closing index",
			holds:
				"a closed session could then be opened and joined again, a resent write applied again, or a closing session left out of the listing that resumes its work",
			remedy: '"noeviction"',
		});
	}
	logger.warn(
		{
			...STORE,
			...(policy === undefined ? {} : { maxmemoryPolicy: policy }),
			...(report.refusal === undefined ? {} : { err: loggableError(report.refusal) }),
		},
		"session_lifecycle_store_eviction_unchecked",
	);
}
