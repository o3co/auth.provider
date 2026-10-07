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
	checkSubjectRevocationInstant,
	clampSubjectRevocationBoundary,
	consoleLogger,
	DEFAULT_CLOCK_SKEW_MS,
	type EventLogger,
	SUBJECT_REVOCATION_MIN_RETENTION_MS,
	type SubjectRevocation,
	type SupportsSessionsOnlyRevocation,
} from "@o3co/auth-provider-core";
import type { SubjectRevocationClient } from "./clients.mjs";
import { requireNoEviction } from "./internal/eviction-policy.mjs";

export interface RedisSubjectRevocationOptions {
	readonly client: SubjectRevocationClient;
	/** Defaults to the bundle's production layout, `ss:rev:`. */
	readonly keyPrefix?: string;
	/** Where a clamped boundary is said, at warn. Absent, `consoleLogger`. */
	readonly logger?: Pick<EventLogger, "warn">;
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
 * command (the client's `advanceRevocationBoundaries`), and the same guard
 * covers the entry's expiry: shortening an in-force watermark would retire the
 * line while tokens it must refuse are still presentable. An expired key is an absent key, so a
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
 * See `packages/core/docs/adr/2026-09-17-federation-grants-offline-delegation.md`.
 *
 * A boundary later than the server's `TIME` plus `DEFAULT_CLOCK_SKEW_MS` is
 * clamped to that in the same script (`advanceRevocationBoundaries`), and the
 * clamp is said at warn after the write; a failing logger never fails the
 * revocation. A client without that method is refused at construction.
 *
 * It resolves once the server's eviction policy passes the gate
 * (`internal/eviction-policy.mts`); a client it cannot use rejects before the
 * server is asked.
 */
export async function createRedisSubjectRevocation(
	deps: RedisSubjectRevocationOptions,
): Promise<SubjectRevocation & SupportsSessionsOnlyRevocation> {
	const revocation = buildRedisSubjectRevocation(deps);
	await requireNoEviction("subjectRevocation", () => deps.client.durability(), {
		reason: "subject-revocation-evictable",
		holds:
			"subjects' revocation watermarks, each keyed with a TTL until the last credential it refuses expires, and a watermark evicted before then lets the subject's earlier sessions and tokens read as not revoked",
	});
	return revocation;
}

function buildRedisSubjectRevocation(
	deps: RedisSubjectRevocationOptions,
): SubjectRevocation & SupportsSessionsOnlyRevocation {
	const prefix = deps.keyPrefix ?? "ss:rev:";
	const key = (subject: string): string => `${prefix}${subject}`;

	// A driver without the clamped write records a boundary as far ahead as a
	// replica's clock runs, refusing the subject's sign-ins until then. So it
	// fails here, at construction, rather than at the first revocation.
	if (
		typeof (deps.client as { advanceRevocationBoundaries?: unknown })
			.advanceRevocationBoundaries !== "function"
	) {
		throw new Error(
			"createRedisSubjectRevocation: this driver has no `advanceRevocationBoundaries`. " +
				"Without it a revocation boundary cannot be clamped to the server's clock, so a " +
				"replica whose clock runs ahead would refuse the subject's sign-ins until its own " +
				"clock's reading. Implement it in the driver (`makeIoredisClients` provides it).",
		);
	}

	const logger = deps.logger ?? consoleLogger;
	const warn = (obj: Record<string, unknown>, msg: string): void => {
		try {
			logger.warn(obj, msg);
		} catch {
			// Only the signal is lost.
		}
	};

	/** What a `Date` can hold: ±100 000 000 days from the epoch (ECMA-262). */
	const MAX_DATE_MS = 8_640_000_000_000_000;

	/**
	 * Records `before`, clamped on the server's clock in the write's own
	 * script, and then says a clamp at warn: the write first, since the
	 * boundary is what ends tokens already issued.
	 */
	const record = async (
		subject: string,
		mode: "all" | "sessions",
		before: Date,
		expiresAt: Date,
	): Promise<void> => {
		const expiresAtMs = checkSubjectRevocationInstant(expiresAt, "expiresAt");
		const beforeMs = checkSubjectRevocationInstant(before, "before");
		const { serverNowMs } = await deps.client.advanceRevocationBoundaries(key(subject), mode, {
			beforeMs,
			expiresAtMs,
			grantRetentionMs: SUBJECT_REVOCATION_MIN_RETENTION_MS,
			skewMs: DEFAULT_CLOCK_SKEW_MS,
		});
		let clamp: ReturnType<typeof clampSubjectRevocationBoundary>;
		try {
			clamp = clampSubjectRevocationBoundary(before, serverNowMs);
		} catch {
			// A clock the client answered that is no instant: the boundary is
			// recorded, and only whether it was clamped is unknown.
			return;
		}
		if (!clamp.clamped) return;
		warn(
			{
				store: "redis",
				subject,
				requestedBefore: new Date(beforeMs).toISOString(),
				recordedBefore: clamp.boundary.toISOString(),
			},
			"subject_revocation_boundary_clamped",
		);
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
			await record(subject, "all", before, expiresAt);
		},

		async revokeSessionsBefore(subject, before, expiresAt) {
			await record(subject, "sessions", before, expiresAt);
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
 * switching between the two keeps the keyspace. A missing `client` rejects at
 * boot rather than failing at the first command.
 */
export const redisSubjectRevocationBuilder: AdapterBuilder<SubjectRevocation> = async (
	config,
	ctx,
) => {
	const c = config as {
		client?: SubjectRevocationClient;
		keyPrefix?: string;
		logger?: Pick<EventLogger, "warn">;
	};
	if (!c.client) {
		throw new Error("redisSubjectRevocationBuilder: 'client' option is required");
	}
	const logger = c.logger ?? ctx?.logger;
	return createRedisSubjectRevocation({
		client: c.client,
		keyPrefix: c.keyPrefix ?? "ss:rev:",
		...(logger !== undefined ? { logger } : {}),
	});
};
