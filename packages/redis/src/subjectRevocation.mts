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

import type { AdapterBuilder, SubjectRevocation } from "@o3co/auth-provider-core";
import type { SubjectRevocationClient } from "./clients.mjs";

/**
 * Redis {@link SubjectRevocation} (#321) — the per-subject not-before
 * watermark, shared across replicas.
 *
 * ## Why the write is not a `SET`
 *
 * The value is one number and the shape looks like `SET key value PX ttl`. It
 * is not, because the watermark is **monotonic**: two credential changes in
 * quick succession, the second computed on a replica whose clock is behind,
 * must not move the line backwards and resurrect every token the first one
 * killed. Last-writer-wins does exactly that. A client-side
 * read-compare-write loses the same race one round-trip later, with two
 * replicas interleaving between the `GET` and the `SET`.
 *
 * So the comparison happens on the server, in one command
 * (`setWatermarkMonotonic`), and the same guard covers the entry's own expiry:
 * shortening an in-force watermark would retire the line while tokens it must
 * refuse are still presentable.
 *
 * An **expired** key is an absent key, so the guard does not resurrect a
 * lapsed watermark's larger value — a reset arriving after the previous
 * watermark timed out starts from its own value, matching the in-process
 * adapter.
 *
 * ## TTL sizing is the caller's contract, not this adapter's
 *
 * `expiresAt` must reach as far as the longest-lived credential the watermark
 * has to refuse — the refresh token, not the access token, wherever the
 * composition forwards `subjectRevocation` to the refresh grant. See
 * `SubjectRevocation` in core for why. This adapter stores what it is given.
 */
export interface RedisSubjectRevocationOptions {
	readonly client: SubjectRevocationClient;
	/** Defaults to the bundle's production layout, `ss:rev:`. */
	readonly keyPrefix?: string;
}

export function createRedisSubjectRevocation(
	deps: RedisSubjectRevocationOptions,
): SubjectRevocation {
	const prefix = deps.keyPrefix ?? "ss:rev:";
	const key = (subject: string): string => `${prefix}${subject}`;

	return {
		kind: "redis",

		async revokeBefore(subject, before, expiresAt) {
			await deps.client.setWatermarkMonotonic(key(subject), before.getTime(), expiresAt.getTime());
		},

		async revokedBefore(subject) {
			const raw = await deps.client.get(key(subject));
			if (raw === null) return null;
			const ms = Number(raw);
			// A value this adapter did not write, or one corrupted in the store, is
			// not a watermark. Answering `null` would silently disable revocation
			// for the subject, so it is refused loudly instead — the caller
			// (`verifyJwt`) already fails closed on a throw from this store.
			if (!Number.isFinite(ms)) {
				throw new Error(
					`SubjectRevocation: watermark for a subject is not a number (key prefix "${prefix}")`,
				);
			}
			return new Date(ms);
		},
	};
}

/**
 * AdapterFactory builder for the Redis-backed `SubjectRevocation` (#321).
 *
 * Use when per-adapter `AdapterFactory` granularity is needed; for the common
 * case the bundled `redisSessionStoresModule` is sufficient. Default
 * `keyPrefix` matches the bundle's production layout (`ss:rev:`) so swapping
 * between bundle and individual builder does not change the keyspace.
 *
 * Missing `client` throws at boot rather than crashing at the first Redis op,
 * matching every other builder in this package.
 */
export const redisSubjectRevocationBuilder: AdapterBuilder<SubjectRevocation> = (config, _ctx) => {
	const c = config as { client?: SubjectRevocationClient; keyPrefix?: string };
	if (!c.client) {
		throw new Error("redisSubjectRevocationBuilder: 'client' option is required");
	}
	return createRedisSubjectRevocation({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "ss:rev:",
	});
};
