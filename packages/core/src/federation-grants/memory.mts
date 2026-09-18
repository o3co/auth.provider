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

import { constantTimeStringEqual } from "../security/timingSafe.mjs";
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
	hasFederationGrantAuthorization,
	type PendingFederationGrant,
} from "./types.mjs";

/** How long a record outlives its expiry, so that the status route can still answer for it (D16). */
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

function copyAuthorization(from: FederationGrantAuthorization): FederationGrantAuthorization {
	// Field by field, and not a spread: what is stored is the authorization and
	// nothing a caller's object happens to carry beside it.
	return {
		identityRevision: from.identityRevision,
		authorizationRevision: from.authorizationRevision,
		upstream: { issuer: from.upstream.issuer, subject: from.upstream.subject },
		...(from.resource !== undefined ? { resource: from.resource } : {}),
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
		...(token !== undefined
			? {
					accessToken: {
						value: token.value,
						tokenType: token.tokenType,
						obtainedAt: new Date(token.obtainedAt),
						issuedLifetime: token.issuedLifetime,
						scopes: [...token.scopes],
					},
				}
			: {}),
	};
}

const credentialDatesAreDates = (credentials: FederationGrantCredentials): boolean =>
	credentials.accessToken === undefined || isDate(credentials.accessToken.obtainedAt);

/**
 * In-process Map-backed {@link FederationGrantStore} (#593, D16).
 *
 * Every write checks and applies with no `await` in between, which on one
 * thread is the atomic step the port asks for. Nothing is sealed: the
 * credentials sit in a Map beside the record, so `unreadable` and
 * `key_unavailable` are states this adapter never reports. What it does keep
 * is everything the contract says about them — one snapshot per `open`, no
 * credential outside `active`, none past the expiry.
 *
 * Two clocks, kept apart as a store with key TTLs keeps them. What a caller is
 * told is judged on the `now` it passes. What is reclaimed — a record nothing
 * can read any more, a credential whose grant has expired — is judged on this
 * process's own clock, whenever an operation touches the record and when a
 * lodging sweeps. So a `now` that is wrong for one call is told the wrong
 * thing once, and costs nothing: the next call finds the record where it was.
 * A listing scans the store, which is what a development adapter can afford.
 *
 * Single-replica only. Grants fork per replica: one lodged, revoked or
 * refreshed on one replica is unknown, still usable or stale on every other,
 * which is why the module that provides this declares itself replica-unsafe
 * and `deployment.mode = "multi"` refuses it by name.
 */
export function createMemoryFederationGrantStore(
	options: MemoryFederationGrantStoreOptions = {},
): MemoryFederationGrantStore {
	const retentionMs =
		options.tombstoneRetentionMs ?? DEFAULT_FEDERATION_GRANT_TOMBSTONE_RETENTION_MS;
	if (!Number.isFinite(retentionMs) || retentionMs < 0) {
		throw new RangeError(
			"createMemoryFederationGrantStore: tombstoneRetentionMs must be a non-negative finite number",
		);
	}

	const entries = new Map<string, Entry>();
	const locks = new Map<string, { expiresAt: number; token: symbol }>();
	let sweepAt = MEMORY_FEDERATION_GRANT_STORE_SWEEP_FLOOR;

	/**
	 * The instant from which the record answers nothing.
	 *
	 * - `pending`: when its first intent lapses, with no retention (D2).
	 * - Authorized, in whatever state it is now: the stored expiry plus the
	 *   retention. A revocation moves no horizon, which is what a store with key
	 *   TTLs does without being asked.
	 * - Revoked while `pending`: it has no expiry, so the revocation plus the
	 *   retention — long enough for the client to be told `revoked`.
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
			// The secret is not (D16).
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

	const tryLock = (
		grantId: string,
		ttlMs: number,
	): { readonly token: symbol; readonly startedAt: number } | null => {
		const held = locks.get(grantId);
		const startedAt = Date.now();
		if (held !== undefined && held.expiresAt > startedAt) return null;
		const token = Symbol("federation-grant-refresh-lock");
		locks.set(grantId, { expiresAt: startedAt + ttlMs, token });
		return { token, startedAt };
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
			// written: a refusal leaves the grant exactly as it was (D7).
			const authorization = input.authorization;
			// The NEW expiry: after this write, and within the ceiling of the new consent.
			if (!(nowMs < authorization.expiresAt.getTime())) return failed();
			if (
				!withinFederationGrantLifetimeCeiling(authorization.consent.at, authorization.expiresAt)
			) {
				return failed();
			}
			// Not dated after this write, with no allowance: a revocation boundary
			// stamped from now on must always cover the consent (D13). Negated, so
			// that a date that is not one is refused as well.
			if (!(authorization.consent.at.getTime() <= nowMs)) return failed();
			if (!(authorization.authorizedAt.getTime() <= nowMs)) return failed();
			if (!credentialDatesAreDates(input.credentials)) return failed();
			// A renewal never re-points a grant: same upstream account, same
			// identity revision (D4, D7). `mayActivate` has refused a revoked grant,
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
				...(grant.lastUsedAt !== undefined ? { lastUsedAt: grant.lastUsedAt } : {}),
			};
			entry.intent = null;
			entry.credentials = copyCredentials(input.credentials);
			return written(entry, next);
		},

		async replaceCredentials(input) {
			const nowMs = instant(input.now, "now");
			const entry = visible(input.grantId, nowMs);
			if (entry === undefined) return failed();
			const grant = entry.grant;
			if (grant.status !== "active" || grant.version !== input.expectedVersion) return failed();
			if (!(nowMs < grant.expiresAt.getTime())) return failed();
			if (!credentialDatesAreDates(input.credentials)) return failed();
			if (input.ineligible !== null && !isDate(input.ineligible.at)) return failed();

			const { ineligible: _cleared, refreshFailure: _forgotten, ...kept } = grant;
			const next: AuthorizedFederationGrant = {
				...kept,
				version: grant.version + 1,
				...(input.ineligible !== null ? { ineligible: copyMarker(input.ineligible) } : {}),
			};
			entry.credentials = copyCredentials(input.credentials);
			return written(entry, next);
		},

		async requireReauthorization(input) {
			const entry = visible(input.grantId, instant(input.now, "now"));
			if (entry === undefined) return failed();
			const grant = entry.grant;
			if (grant.status !== "active" || grant.version !== input.expectedVersion) return failed();

			entry.credentials = null;
			const { refreshFailure: _forgotten, ...kept } = grant;
			return written(entry, {
				...kept,
				status: "reauthorization_required",
				version: grant.version + 1,
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
			const { refreshFailure: _forgotten, ...kept } = grant;
			return written(entry, {
				...kept,
				status: "revoked",
				version: grant.version + 1,
				revocation: { by, at: new Date(atMs) },
			});
		},

		async noteRefreshFailure(input) {
			const nowMs = instant(input.now, "now");
			const entry = visible(input.grantId, nowMs);
			if (entry === undefined) return failed();
			const grant = entry.grant;
			if (grant.status !== "active" || grant.version !== input.expectedVersion) return failed();
			if (!(nowMs < grant.expiresAt.getTime())) return failed();
			if (!isDate(input.failure.at)) return failed();
			const { retryAfterSeconds, upstreamCode } = input.failure;
			const atMs = input.failure.at.getTime();
			const previous = grant.refreshFailure;
			// Never back: a stamp that outlived its caller's budget arrives after a
			// newer one, and must not replace it.
			if (previous !== undefined && atMs < previous.at.getTime()) return failed();
			// A row: the stamp it replaces is no further back than `rowMs`.
			const inRow = previous !== undefined && atMs - previous.at.getTime() <= input.rowMs;
			// In place, in one step: a stamp read, counted and written in three
			// would lose to a touch, and a count to a second stamp.
			const next: AuthorizedFederationGrant = {
				...grant,
				refreshFailure: {
					at: new Date(atMs),
					kind: input.failure.kind,
					count: inRow ? previous.count + 1 : 1,
					...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}),
					...(upstreamCode !== undefined ? { upstreamCode } : {}),
				},
			};
			return written(entry, next);
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
			// off, and two refreshes would present one refresh token (D12).
			if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
				throw new RangeError("acquireRefreshLock: ttlMs must be a positive finite number");
			}
			if (!Number.isFinite(waitForMs) || waitForMs < 0) {
				throw new RangeError("acquireRefreshLock: waitForMs must be a non-negative finite number");
			}
			const askedAt = Date.now();
			const deadline = askedAt + waitForMs;
			let taken = tryLock(grantId, ttlMs);
			while (taken === null) {
				// The deadline is looked at BEFORE every further try, and the wait
				// never runs past it: a lock released between the deadline and the
				// next poll is not taken, since the caller has given up by then.
				const remaining = deadline - Date.now();
				if (remaining <= 0) return { acquired: false, reason: "timeout" };
				await new Promise((resolve) =>
					setTimeout(resolve, Math.min(LOCK_POLL_INTERVAL_MS, remaining)),
				);
				if (Date.now() >= deadline) return { acquired: false, reason: "timeout" };
				taken = tryLock(grantId, ttlMs);
			}
			const held = taken.token;
			return {
				acquired: true,
				waitedMs: taken.startedAt - askedAt,
				release: async () => {
					// Only while it is still this holder's: past the TTL another
					// caller may hold the lock, and that one is not ours to free.
					if (locks.get(grantId)?.token === held) locks.delete(grantId);
				},
			};
		},
	};
}
