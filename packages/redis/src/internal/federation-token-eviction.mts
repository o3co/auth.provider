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
 * that lives about 2 s; a policy that may evict that key lets a resent copy
 * write again (an older record back over a later write, or a logged-out
 * session's tokens back). So any policy but `noeviction` is one warning. A
 * policy that could not be read, or a server that could not answer, is one
 * info line. Neither stops the boot.
 */

import { type Logger, loggableError } from "@o3co/auth-provider-core";
import type { RedisDurability } from "../clients.mjs";

const STORE = { store: "federation-tokens", adapter: "redis" } as const;

/** Reads the policy once through `durability` and writes at most one line on `logger`. */
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
	if (policy === undefined) {
		logger.info(
			{
				...STORE,
				...(report.refusal === undefined ? {} : { err: loggableError(report.refusal) }),
			},
			"federation_token_store_eviction_unchecked",
		);
		return;
	}
	if (policy !== "noeviction") {
		logger.warn({ ...STORE, maxmemoryPolicy: policy }, "federation_token_store_evictable");
	}
}
