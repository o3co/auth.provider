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

import { isStorableLifetime } from "../adapters/expiry.mjs";
import { constantTimeStringEqual } from "../security/timingSafe.mjs";
import {
	federationGrantInteractionCode,
	federationGrantRefreshFailureStamp,
} from "./eligibility.mjs";
import { withinFederationGrantLifetimeCeiling } from "./lifetime.mjs";
import type {
	FederationGrantCredentialState,
	FederationGrantIntentPointer,
	FederationGrantLockResult,
	FederationGrantStore,
	FederationGrantWrite,
} from "./store.mjs";
import {
	type AuthorizedFederationGrant,
	type FederationGrant,
	type FederationGrantAuthorization,
	type FederationGrantCredentials,
	type FederationGrantIneligibilityMarker,
	type FederationGrantRotations,
	hasFederationGrantAuthorization,
	type PendingFederationGrant,
} from "./types.mjs";

/** How long a record outlives its expiry, so that the status route can still answer for it. */
export const DEFAULT_FEDERATION_GRANT_TOMBSTONE_RETENTION_MS = 30 * 86_400_000;

/**
 * Sweep once the store holds this many records, and then again each time it
 * has doubled: a connect the user never finishes leaves a `pending` record
 * nobody reads again, under an ID nobody lodges again, and reclaiming on touch
 * alone would keep every one of them. Amortized, with no timer of its own, as
 * the pending-consent store does.
 */
export const MEMORY_FEDERATION_GRANT_STORE_SWEEP_FLOOR = 1024;

const LOCK_POLL_INTERVAL_MS = 25;

export interface MemoryFederationGrantStoreOptions {
	/**
	 * Milliseconds a record is retained past its expiry — or, for a grant
	 * revoked while `pending`, past its revocation. Default
	 * {@link DEFAULT_FEDERATION_GRANT_TOMBSTONE_RETENTION_MS}. A credential gets
	 * none: it is never disclosed from the expiry on, and it is dropped by
	 * whatever touches the record next once this process's clock has passed it.
	 */
	readonly tombstoneRetentionMs?: number;
}

/** In-process grant store, with what is resident exposed for observability. */
export interface MemoryFederationGrantStore extends FederationGrantStore {
	/** Records currently resident, reclaimable-but-unreclaimed included. */
	readonly size: number;
	/**
	 * Whether a credential is resident for the grant. Through the port a grant
	 * that is not `active` reads as `absent` whether its secret was deleted or is
	 * only hidden; this is what tells the two apart. Touches nothing.
	 */
	holdsCredential(grantId: string): boolean;
}

interface Entry {
	grant: FederationGrant;
	/** `null` once retired: by the activation it led to, by a revocation, or by name. */
	intent: FederationGrantIntentPointer | null;
	credentials: FederationGrantCredentials | null;
}

/** A fresh object each time: a result a caller changed must not be another caller's. */
const failed = (): FederationGrantWrite => ({ ok: false });

/**
 * The instant as a number. An invalid date is refused, and not compared: every
 * comparison with NaN is false, so a rule phrased "is it still before?" would
 * read an invalid `now` as "everything has lapsed".
 */
function instant(date: Date, name: string): number {
	const ms = date.getTime();
	if (Number.isNaN(ms)) throw new RangeError(`FederationGrantStore: ${name} is not a valid date`);
	return ms;
}

const isDate = (date: Date): boolean => !Number.isNaN(date.getTime());

/** A copy of a real `Date` holding an instant, read by its own value and never through a method it may override; `undefined` for anything else. */
const instantCopy = (value: unknown): Date | undefined => {
	try {
		const ms = Date.prototype.getTime.call(value);
		return Number.isNaN(ms) ? undefined : new Date(ms);
	} catch {
		return undefined;
	}
};

function copyAuthorization(from: FederationGrantAuthorization): FederationGrantAuthorization {
	// Field by field, and not a spread: what is stored is the authorization and
	// nothing a caller's object happens to carry beside it.
	return {
		identityRevision: from.identityRevision,
		authorizationRevision: from.authorizationRevision,
		upstream: { issuer: from.upstream.issuer, subject: from.upstream.subject },
		resource: from.resource,
		scopes: [...from.scopes],
		consent: {
			at: new Date(from.consent.at),
			sid: from.consent.sid,
			scopes: [...from.consent.scopes],
		},
		authorizedAt: new Date(from.authorizedAt),
		expiresAt: new Date(from.expiresAt),
	};
}

function copyMarker(from: FederationGrantIneligibilityMarker): FederationGrantIneligibilityMarker {
	return { reason: from.reason, at: new Date(from.at), judgedAgainst: from.judgedAgainst };
}

function copyCredentials(from: FederationGrantCredentials): FederationGrantCredentials {
	const token = from.accessToken;
	return {
		refreshToken: from.refreshToken,
		accessToken:
			token === undefined
				? undefined
				: {
						value: token.value,
						tokenType: token.tokenType,
						obtainedAt: new Date(token.obtainedAt),
						issuedLifetime: token.issuedLifetime,
						...(token.effectiveExpiresAt === undefined
							? {}
							: { effectiveExpiresAt: new Date(token.effectiveExpiresAt) }),
						scopes: [...token.scopes],
					},
	};
}

/**
 * The copy of the credentials a store keeps, or `undefined` when they are not
 * ones it can: the access token's dates are dates, and its issued lifetime a
 * finite number. Each field is read once, and what was judged is what is
 * stored. A lifetime of NaN or infinity is refused at the write, where every
 * adapter refuses it alike, rather than kept here and read back as unreadable
 * by an adapter that seals what it stores.
 */
const storableCredentials = (
	credentials: FederationGrantCredentials,
): FederationGrantCredentials | undefined => {
	const refreshToken = credentials.refreshToken;
	const token = credentials.accessToken;
	if (token === undefined) return { refreshToken, accessToken: undefined };
	const obtainedAt = instantCopy(token.obtainedAt);
	const issuedLifetime = token.issuedLifetime;
	const effective = token.effectiveExpiresAt;
	const effectiveExpiresAt = effective === undefined ? undefined : instantCopy(effective);
	if (
		obtainedAt === undefined ||
		!Number.isFinite(issuedLifetime) ||
		(effective !== undefined && effectiveExpiresAt === undefined)
	) {
		return undefined;
	}
	return {
		refreshToken,
		accessToken: {
			value: token.value,
			tokenType: token.tokenType,
			obtainedAt,
			issuedLifetime,
			...(effectiveExpiresAt === undefined ? {} : { effectiveExpiresAt }),
			scopes: [...token.scopes],
		},
	};
};

/**
 * In-process Map-backed {@link FederationGrantStore}.
 *
 * Every write checks and applies with no `await` in between, which is the
 * atomic step the port asks for. Nothing is sealed, so `unreadable` and
 * `key_unavailable` never occur; the other credential rules hold (one
 * snapshot per `open`, none outside `active`, none past the expiry).
 *
 * Two clocks, as a store with key TTLs has: what a caller is told is judged
 * on the `now` it passes; what is reclaimed is judged on this process's clock
 * when a record is touched or a lodging sweeps. A wrong `now` misleads one
 * call and destroys nothing.
 *
 * Single-replica only: grants fork per replica, so the module declares
 * itself replica-unsafe and `core.deployment.mode = "multi"` refuses it.
 */
export function createMemoryFederationGrantStore(
	options: MemoryFederationGrantStoreOptions = {},
): MemoryFederationGrantStore {
	// Within the Date range, as the Redis store requires: past it a
	// tombstone's horizon is no deadline a key can carry, and the two adapters
	// give one answer to one setting.
	const retentionMs =
		options.tombstoneRetentionMs ?? DEFAULT_FEDERATION_GRANT_TOMBSTONE_RETENTION_MS;
	if (!isStorableLifetime(retentionMs, { allowZero: true })) {
		throw new RangeError(
			"createMemoryFederationGrantStore: tombstoneRetentionMs must be a non-negative number of milliseconds that ends within the Date range",
		);
	}

	const entries = new Map<string, Entry>();
	const locks = new Map<string, { expiresAt: number; token: symbol }>();
	let sweepAt = MEMORY_FEDERATION_GRANT_STORE_SWEEP_FLOOR;

	/**
	 * The instant from which the record answers nothing.
	 *
	 * - `pending`: when its first intent lapses, with no retention.
	 * - Authorized, in any state: the stored expiry plus the retention (a
	 *   revocation moves no horizon).
	 * - Revoked while `pending`: the revocation plus the retention.
	 */
	const goneAt = (entry: Entry): number => {
		const grant = entry.grant;
		if (grant.status === "pending") return entry.intent?.expiresAt.getTime() ?? 0;
		if (hasFederationGrantAuthorization(grant)) return grant.expiresAt.getTime() + retentionMs;
		return grant.revocation.at.getTime() + retentionMs;
	};

	/** Reclaims on this process's clock; says whether the entry is still resident. */
	const reclaim = (grantId: string, entry: Entry, wallMs: number): boolean => {
		if (!(wallMs < goneAt(entry))) {
			entries.delete(grantId);
			return false;
		}
		const grant = entry.grant;
		if (
			entry.credentials !== null &&
			hasFederationGrantAuthorization(grant) &&
			!(wallMs < grant.expiresAt.getTime())
		) {
			// The record is retained so that the status route can answer for it.
			// The secret is not.
			entry.credentials = null;
		}
		return true;
	};

	/** The entry as a caller at `nowMs` may see it: resident, and not gone at that instant. */
	const visible = (grantId: string, nowMs: number): Entry | undefined => {
		const entry = entries.get(grantId);
		if (entry === undefined || !reclaim(grantId, entry, Date.now())) return undefined;
		return nowMs < goneAt(entry) ? entry : undefined;
	};

	const sweep = (): void => {
		const wallMs = Date.now();
		for (const [grantId, entry] of [...entries]) reclaim(grantId, entry, wallMs);
		sweepAt = Math.max(MEMORY_FEDERATION_GRANT_STORE_SWEEP_FLOOR, entries.size * 2);
	};

	/**
	 * Whether an activation with `handle` could still succeed, as far as the
	 * record says: the grant is not revoked, its consented lifetime has not
	 * ended, and the handle is its current intent, not yet lapsed.
	 */
	const mayActivate = (entry: Entry, handle: string, nowMs: number): boolean => {
		const grant = entry.grant;
		if (grant.status === "revoked") return false;
		// The STORED expiry: a new consent must not resurrect a grant whose
		// consented lifetime has ended. "Unless pending" — not "if active".
		if (grant.status !== "pending" && !(nowMs < grant.expiresAt.getTime())) return false;
		return (
			entry.intent !== null &&
			constantTimeStringEqual(entry.intent.handle, handle) &&
			nowMs < entry.intent.expiresAt.getTime()
		);
	};

	/**
	 * What `open` may hand out at `nowMs`. Only an `active` grant has a
	 * credential; the status is checked all the same, so that a transition which
	 * forgot to delete one would still disclose nothing. And none from the
	 * stored expiry on, whether or not this process's clock has reclaimed it.
	 */
	const credentialsAt = (entry: Entry, nowMs: number): FederationGrantCredentials | null => {
		const grant = entry.grant;
		if (grant.status !== "active" || !(nowMs < grant.expiresAt.getTime())) return null;
		return entry.credentials;
	};

	const written = (entry: Entry, grant: FederationGrant): FederationGrantWrite => {
		entry.grant = grant;
		return { ok: true, grant: structuredClone(grant) };
	};

	/** Takes the lock if nobody holds it. The lease is on this process's clock, as a key TTL is on the server's. */
	const tryLock = (grantId: string, ttlMs: number): symbol | null => {
		const held = locks.get(grantId);
		const wallMs = Date.now();
		if (held !== undefined && held.expiresAt > wallMs) return null;
		const token = Symbol("federation-grant-refresh-lock");
		locks.set(grantId, { expiresAt: wallMs + ttlMs, token });
		return token;
	};

	return {
		kind: "memory",

		get size() {
			return entries.size;
		},

		holdsCredential(grantId) {
			return (entries.get(grantId)?.credentials ?? null) !== null;
		},

		async createPending(input) {
			const nowMs = instant(input.now, "now");
			// An intent that has already lapsed creates nothing, and so does one
			// whose expiry is not a date: `nowMs < NaN` is false.
			if (!(nowMs < input.intent.expiresAt.getTime())) return failed();
			// Taken while the record is RESIDENT, and not merely while this caller
			// can see it: a caller whose clock is ahead must not lodge over a record
			// that is still there for everyone else.
			const resident = entries.get(input.id);
			if (resident !== undefined && reclaim(input.id, resident, Date.now())) return failed();
			if (entries.size >= sweepAt) sweep();

			const grant: PendingFederationGrant = {
				id: input.id,
				subject: input.subject,
				clientId: input.clientId,
				connection: input.connection,
				status: "pending",
				createdAt: new Date(nowMs),
				version: 1,
			};
			const entry: Entry = {
				grant,
				intent: { handle: input.intent.handle, expiresAt: new Date(input.intent.expiresAt) },
				credentials: null,
			};
			entries.set(input.id, entry);
			return written(entry, grant);
		},

		async nameIntent(input) {
			const nowMs = instant(input.now, "now");
			if (!(nowMs < input.intent.expiresAt.getTime())) return failed();
			const entry = visible(input.grantId, nowMs);
			if (entry === undefined) return failed();
			const grant = entry.grant;
			if (grant.status !== "active" && grant.status !== "reauthorization_required") return failed();
			if (!(nowMs < grant.expiresAt.getTime())) return failed();

			entry.intent = {
				handle: input.intent.handle,
				expiresAt: new Date(input.intent.expiresAt),
			};
			return written(entry, grant);
		},

		async isCurrentIntent(grantId, handle, now) {
			const nowMs = instant(now, "now");
			const entry = visible(grantId, nowMs);
			return entry !== undefined && mayActivate(entry, handle, nowMs);
		},

		async retireIntent(input) {
			const nowMs = instant(input.now, "now");
			const entry = visible(input.grantId, nowMs);
			if (entry === undefined || entry.intent === null) return failed();
			const grant = entry.grant;
			// A pending grant's first intent is its life: revoking the grant ends that.
			if (grant.status !== "active" && grant.status !== "reauthorization_required") return failed();
			if (
				input.handle !== undefined &&
				!constantTimeStringEqual(entry.intent.handle, input.handle)
			) {
				return failed();
			}

			entry.intent = null;
			return written(entry, grant);
		},

		async find(grantId, now) {
			const entry = visible(grantId, instant(now, "now"));
			return entry === undefined ? null : structuredClone(entry.grant);
		},

		async listBySubject(subject, now) {
			const nowMs = instant(now, "now");
			const grants: FederationGrant[] = [];
			for (const grantId of [...entries.keys()]) {
				const entry = visible(grantId, nowMs);
				if (entry !== undefined && entry.grant.subject === subject) {
					grants.push(structuredClone(entry.grant));
				}
			}
			return grants;
		},

		async inspect(grantId, now) {
			const nowMs = instant(now, "now");
			const entry = visible(grantId, nowMs);
			if (entry === undefined) return null;
			const credentials: FederationGrantCredentialState =
				credentialsAt(entry, nowMs) === null ? "absent" : "ok";
			return { grant: structuredClone(entry.grant), credentials };
		},

		async open(grantId, now) {
			const nowMs = instant(now, "now");
			const entry = visible(grantId, nowMs);
			if (entry === undefined) return null;
			const credentials = credentialsAt(entry, nowMs);
			return {
				grant: structuredClone(entry.grant),
				credentials:
					credentials === null
						? { state: "absent" }
						: { state: "ok", value: copyCredentials(credentials) },
			};
		},

		async activate(input) {
			const nowMs = instant(input.now, "now");
			const entry = visible(input.grantId, nowMs);
			if (entry === undefined) return failed();
			if (!mayActivate(entry, input.intentHandle, nowMs)) return failed();

			// What the activation carries, all of it checked before anything is
			// written: a refusal leaves the grant exactly as it was.
			const authorization = input.authorization;
			// The NEW expiry: after this write, and within the ceiling of the new consent.
			if (!(nowMs < authorization.expiresAt.getTime())) return failed();
			if (
				!withinFederationGrantLifetimeCeiling(authorization.consent.at, authorization.expiresAt)
			) {
				return failed();
			}
			// Not dated after this write, with no allowance: a revocation boundary
			// stamped from now on must always cover the consent. Negated, so
			// that a date that is not one is refused as well.
			if (!(authorization.consent.at.getTime() <= nowMs)) return failed();
			if (!(authorization.authorizedAt.getTime() <= nowMs)) return failed();
			const credentials = storableCredentials(input.credentials);
			if (credentials === undefined) return failed();
			// A renewal never re-points a grant: same upstream account, same
			// identity revision. `mayActivate` has refused a revoked grant,
			// so one that has an authorization here is `active` or needs the user.
			const grant = entry.grant;
			if (
				hasFederationGrantAuthorization(grant) &&
				(grant.identityRevision !== authorization.identityRevision ||
					grant.upstream.issuer !== authorization.upstream.issuer ||
					grant.upstream.subject !== authorization.upstream.subject)
			) {
				return failed();
			}

			// Built from the base fields, and not spread over the old record: the
			// authorization is replaced as a whole, and the marker goes with it.
			const next: AuthorizedFederationGrant = {
				id: grant.id,
				subject: grant.subject,
				clientId: grant.clientId,
				connection: grant.connection,
				status: "active",
				createdAt: grant.createdAt,
				version: grant.version + 1,
				...copyAuthorization(authorization),
				lastUsedAt: grant.lastUsedAt,
				// The authorization is replaced, so what was judged against the
				// old one goes with it, and the rotation budget starts afresh.
				ineligible: undefined,
				refreshFailure: undefined,
				rotations: undefined,
			};
			entry.intent = null;
			entry.credentials = credentials;
			return written(entry, next);
		},

		async replaceCredentials(input) {
			const nowMs = instant(input.now, "now");
			const entry = visible(input.grantId, nowMs);
			if (entry === undefined) return failed();
			const grant = entry.grant;
			if (grant.status !== "active" || grant.version !== input.expectedVersion) return failed();
			if (!(nowMs < grant.expiresAt.getTime())) return failed();
			// The credential it replaces must still be there. One this process's
			// clock has reclaimed is not written back by a caller whose clock is
			// behind, as a key TTL that has fired is not: that same caller
			// would read the new one as `absent` a call later.
			if (entry.credentials === null) return failed();
			const credentials = storableCredentials(input.credentials);
			if (credentials === undefined) return failed();
			if (input.ineligible !== null && !isDate(input.ineligible.at)) return failed();
			// A maximum that is not a finite number is not one the marker was judged
			// against, nor one every adapter can keep.
			if (input.ineligible !== null && !Number.isFinite(input.ineligible.judgedAgainst)) {
				return failed();
			}

			const next: AuthorizedFederationGrant = {
				...grant,
				version: grant.version + 1,
				ineligible: input.ineligible === null ? undefined : copyMarker(input.ineligible),
				refreshFailure: undefined,
			};
			entry.credentials = credentials;
			return written(entry, next);
		},

		async requireReauthorization(input) {
			const entry = visible(input.grantId, instant(input.now, "now"));
			if (entry === undefined) return failed();
			const grant = entry.grant;
			if (grant.status !== "active" || grant.version !== input.expectedVersion) return failed();

			entry.credentials = null;
			return written(entry, {
				...grant,
				status: "reauthorization_required",
				version: grant.version + 1,
				refreshFailure: undefined,
			});
		},

		async revoke(grantId, by, at) {
			const atMs = instant(at, "at");
			const entry = visible(grantId, atMs);
			if (entry === undefined) return failed();
			const grant = entry.grant;
			// The first revocation stays as recorded.
			if (grant.status === "revoked") return failed();

			entry.intent = null;
			entry.credentials = null;
			const revocation = {
				status: "revoked" as const,
				version: grant.version + 1,
				revocation: { by, at: new Date(atMs) },
			};
			// A grant never authorized has no usage fields to clear; one that was
			// keeps them, the failure stamp cleared with the credentials it was
			// about.
			return written(
				entry,
				grant.status === "pending"
					? { ...grant, ...revocation }
					: { ...grant, refreshFailure: undefined, ...revocation },
			);
		},

		async noteRefreshFailure(input) {
			const nowMs = instant(input.now, "now");
			const entry = visible(input.grantId, nowMs);
			if (entry === undefined) return failed();
			const grant = entry.grant;
			if (grant.status !== "active" || grant.version !== input.expectedVersion) return failed();
			if (!(nowMs < grant.expiresAt.getTime())) return failed();
			// Each field read once, by name, and not spread: a report's fields may
			// be accessors, and what was judged is what is stamped.
			const { at, kind, retryAfterSeconds: retryAfter, upstreamCode } = input.failure;
			if (!isDate(at)) return failed();
			// A backoff that is not a finite number is not one the classifier
			// bounded, nor one every adapter can keep.
			if (retryAfter !== undefined && !Number.isFinite(retryAfter)) return failed();
			const atMs = at.getTime();
			const previous = grant.refreshFailure;
			// Never back: a stamp that outlived its caller's budget arrives after a
			// newer one, and must not replace it.
			if (previous !== undefined && atMs < previous.at.getTime()) return failed();
			// Never over the user: a stamp that says the user has to
			// come back is what the grant reads as `reauthorization_required`, and
			// no later outage, rate limit or refusal says otherwise. Only what
			// replaces or ends the credentials clears it.
			if (federationGrantInteractionCode(previous) !== undefined) return failed();
			// A row: the stamp it replaces is no further back than `rowMs`.
			const inRow = previous !== undefined && atMs - previous.at.getTime() <= input.rowMs;
			// In place, in one step: a stamp read, counted and written in three
			// would lose to a touch, and a count to a second stamp.
			const next: AuthorizedFederationGrant = {
				...grant,
				refreshFailure: federationGrantRefreshFailureStamp(
					{ at: new Date(atMs), kind, retryAfterSeconds: retryAfter, upstreamCode },
					inRow ? previous.count + 1 : 1,
				),
			};
			return written(entry, next);
		},

		async takeRotation(input) {
			const nowMs = instant(input.now, "now");
			if (!Number.isSafeInteger(input.limit) || input.limit < 1) {
				throw new RangeError("takeRotation: limit must be a whole number of at least 1");
			}
			if (!Number.isFinite(input.windowMs) || input.windowMs <= 0) {
				throw new RangeError("takeRotation: windowMs must be a positive finite number");
			}
			const entry = visible(input.grantId, nowMs);
			if (entry === undefined) return failed();
			const grant = entry.grant;
			if (grant.status !== "active" || grant.version !== input.expectedVersion) return failed();
			if (!(nowMs < grant.expiresAt.getTime())) return failed();
			// Checked and counted with no await in between, so takes at once are
			// each counted.
			const previous = grant.rotations;
			let rotations: FederationGrantRotations;
			// A `since` that holds no instant is no window: this take opens one.
			if (previous === undefined || !(nowMs < previous.since.getTime() + input.windowMs)) {
				rotations = { since: new Date(nowMs), count: 1 };
			} else if (previous.count < input.limit) {
				rotations = { since: new Date(previous.since), count: previous.count + 1 };
			} else {
				return failed();
			}
			return written(entry, { ...grant, version: grant.version + 1, rotations });
		},

		async refundRotation(input) {
			const nowMs = instant(input.now, "now");
			const sinceMs = instant(input.since, "since");
			const entry = visible(input.grantId, nowMs);
			if (entry === undefined) return failed();
			const grant = entry.grant;
			if (grant.status !== "active" || grant.version !== input.expectedVersion) return failed();
			if (!(nowMs < grant.expiresAt.getTime())) return failed();
			const previous = grant.rotations;
			if (
				previous === undefined ||
				previous.since.getTime() !== sinceMs ||
				!(previous.count >= 1)
			) {
				return failed();
			}
			// The bump is what makes it once per attempt.
			return written(entry, {
				...grant,
				version: grant.version + 1,
				rotations: { since: new Date(sinceMs), count: previous.count - 1 },
			});
		},

		async touch(grantId, at) {
			const atMs = at.getTime();
			if (Number.isNaN(atMs)) return;
			const entry = visible(grantId, atMs);
			if (entry === undefined || entry.grant.status !== "active") return;
			// Never back: two retrievals may report out of order.
			const last = entry.grant.lastUsedAt;
			if (last !== undefined && !(last.getTime() < atMs)) return;
			entry.grant = { ...entry.grant, lastUsedAt: new Date(atMs) };
		},

		async acquireRefreshLock(grantId, { ttlMs, waitForMs }): Promise<FederationGrantLockResult> {
			// A TTL of NaN compares as already expired: exclusion would be silently
			// off, and two refreshes would present one refresh token.
			// And each must end within the Date range: a lease or a wait past it
			// is one no clock reaches the end of.
			if (!isStorableLifetime(ttlMs)) {
				throw new RangeError("acquireRefreshLock: ttlMs must be a positive finite number");
			}
			if (!isStorableLifetime(waitForMs, { allowZero: true })) {
				throw new RangeError("acquireRefreshLock: waitForMs must be a non-negative finite number");
			}
			// The wait and its deadline are measured on the monotonic clock, as the
			// Redis lock measures them: `Date.now()` steps when the host's clock is
			// set, and a wait would then be reported as negative, or as hours, and
			// core would refuse the lease of a lock that was in fact taken at once
			// The lease itself stays on this process's clock, in `tryLock`.
			const askedAt = performance.now();
			const deadline = askedAt + waitForMs;
			// Rounded DOWN to a whole millisecond, as the Redis lock rounds: a
			// lower bound on when the lease began, taken immediately before the
			// attempt that succeeded was made.
			let waitedMs = 0;
			let held = tryLock(grantId, ttlMs);
			while (held === null) {
				// The deadline is looked at BEFORE every further try, and the wait
				// never runs past it: a lock released between the deadline and the
				// next poll is not taken, since the caller has given up by then.
				const remaining = deadline - performance.now();
				if (remaining <= 0) return { acquired: false, reason: "timeout" };
				await new Promise((resolve) =>
					setTimeout(resolve, Math.min(LOCK_POLL_INTERVAL_MS, remaining)),
				);
				if (performance.now() >= deadline) return { acquired: false, reason: "timeout" };
				waitedMs = Math.floor(performance.now() - askedAt);
				held = tryLock(grantId, ttlMs);
			}
			return {
				acquired: true,
				waitedMs,
				release: async () => {
					// Only while it is still this holder's: past the TTL another
					// caller may hold the lock, and that one is not ours to free.
					if (locks.get(grantId)?.token === held) locks.delete(grantId);
				},
			};
		},
	};
}
