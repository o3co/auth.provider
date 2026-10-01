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

import {
	type AdapterBuilder,
	SUBJECT_REVOCATION_MIN_RETENTION_MS,
	type SubjectRevocation,
	type SupportsSessionsOnlyRevocation,
} from "@o3co/auth-provider-core";
import type { SubjectRevocationClient } from "./clients.mjs";

export interface RedisSubjectRevocationOptions {
	readonly client: SubjectRevocationClient;
	/** Defaults to the bundle's production layout, `ss:rev:`. */
	readonly keyPrefix?: string;
}

/**
 * Redis {@link SubjectRevocation}: the per-subject not-before watermark,
 * shared across replicas.
 *
 * The write is not a `SET`, because the watermark is monotonic: two credential
 * changes in quick succession, the second computed on a replica whose clock is
 * behind, must not move the line back and resurrect every token the first one
 * killed. Last-writer-wins does that, and a client-side read-compare-write
 * does it one round-trip later. So the comparison runs on the server in one
 * command (`setRevocationBoundaries`), and the same guard covers the entry's
 * expiry: shortening an in-force watermark would retire the line while tokens
 * it must refuse are still presentable. An expired key is an absent key, so a
 * reset after the previous watermark lapsed starts from its own value, as in
 * the in-process adapter.
 *
 * `expiresAt` must reach as far as the longest-lived credential the watermark
 * has to refuse; core's `resolveSubjectRevocationHorizonMs` sizes it, and this
 * adapter stores what it is given, except that a write which advances the
 * grants boundary raises the stored expiry to
 * `SUBJECT_REVOCATION_MIN_RETENTION_MS` past that boundary. That floor is not
 * the caller's to shorten: it must outlive a grant lifetime the code bounds
 * absolutely, even when the caller knows nothing of grants. A sessions-only
 * stamp sets no such floor.
 * See ADR 2026-09-17-federation-grants-offline-delegation, D13.
 */
export function createRedisSubjectRevocation(
	deps: RedisSubjectRevocationOptions,
): SubjectRevocation & SupportsSessionsOnlyRevocation {
	const prefix = deps.keyPrefix ?? "ss:rev:";
	const key = (subject: string): string => `${prefix}${subject}`;

	// A driver without `setRevocationBoundaries` cannot express a
	// sessions-only stamp, and one that quietly ignored the mode would answer
	// every such stamp by revoking the subject's grants, the one operation the
	// caller asked not to perform. So it fails here, at construction, rather
	// than at the first password change.
	if (
		typeof (deps.client as { setRevocationBoundaries?: unknown }).setRevocationBoundaries !==
		"function"
	) {
		throw new Error(
			"createRedisSubjectRevocation: this driver has no `setRevocationBoundaries`. " +
				"Without it a driver can advance only one revocation boundary, so a sessions-only " +
				"stamp made through it would revoke the subject's federation grants. Upgrade the " +
				"driver rather than the adapter.",
		);
	}

	/** What a `Date` can hold: ±100 000 000 days from the epoch (ECMA-262). */
	const MAX_DATE_MS = 8_640_000_000_000_000;

	/** Every comparison with NaN is false, so a NaN boundary covers nothing while looking like one. */
	const instant = (value: Date, name: string): number => {
		const ms = value?.getTime?.();
		if (typeof ms !== "number" || Number.isNaN(ms)) {
			throw new RangeError(`SubjectRevocation: ${name} must be a date`);
		}
		return ms;
	};

	/**
	 * The stored value, in the two forms the script writes, or a bare decimal
	 * (what older releases wrote), which means both boundaries. Anything else
	 * is refused rather than read as `null`: "nothing was revoked" for a value
	 * this adapter does not understand would silently disable revocation for
	 * that subject, and `verifyJwt` already fails closed on a throw from this
	 * store.
	 */
	const decode = (raw: string): { sessionsMs: number; grantsMs: number | null } => {
		if (/^-?\d+$/.test(raw)) {
			const both = boundary(raw);
			return { sessionsMs: both, grantsMs: both };
		}
		const parsed = /^v1:(-?\d+):(-?\d+|-)$/.exec(raw);
		if (parsed === null) {
			throw new Error(
				`SubjectRevocation: the record for a subject is not a watermark (key prefix "${prefix}")`,
			);
		}
		return {
			sessionsMs: boundary(parsed[1] as string),
			grantsMs: parsed[2] === "-" ? null : boundary(parsed[2] as string),
		};
	};

	/**
	 * Digits are not yet a date: `Number("9".repeat(400))` is `Infinity`, which
	 * passes every shape check above. `new Date(Infinity)` is an Invalid Date,
	 * every comparison against it is false, and the subject would read as
	 * having revoked nothing: revocation silently off. So the value has to be a
	 * date a `Date` can hold, and anything else is an outage.
	 */
	const boundary = (digits: string): number => {
		const ms = Number(digits);
		if (!Number.isSafeInteger(ms) || Math.abs(ms) > MAX_DATE_MS) {
			throw new Error(
				`SubjectRevocation: the record for a subject is not a watermark (key prefix "${prefix}")`,
			);
		}
		return ms;
	};

	const read = async (subject: string) => {
		const raw = await deps.client.get(key(subject));
		return raw === null ? null : decode(raw);
	};

	return {
		kind: "redis",

		async revokeBefore(subject, before, expiresAt) {
			await deps.client.setRevocationBoundaries(
				key(subject),
				"all",
				instant(before, "before"),
				instant(expiresAt, "expiresAt"),
				SUBJECT_REVOCATION_MIN_RETENTION_MS,
			);
		},

		async revokeSessionsBefore(subject, before, expiresAt) {
			await deps.client.setRevocationBoundaries(
				key(subject),
				"sessions",
				instant(before, "before"),
				instant(expiresAt, "expiresAt"),
				SUBJECT_REVOCATION_MIN_RETENTION_MS,
			);
		},

		async revokedBefore(subject) {
			const record = await read(subject);
			return record === null ? null : new Date(record.sessionsMs);
		},

		async grantsRevokedBefore(subject) {
			const record = await read(subject);
			return record?.grantsMs == null ? null : new Date(record.grantsMs);
		},
	};
}

/**
 * AdapterFactory builder for the Redis-backed `SubjectRevocation`, for
 * per-adapter granularity; the bundled `redisSessionStoresModule` covers the
 * common case. The default `keyPrefix` is the bundle's (`ss:rev:`), so
 * switching between the two keeps the keyspace. A missing `client` throws at
 * boot, as in every other builder here, rather than at the first command.
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
