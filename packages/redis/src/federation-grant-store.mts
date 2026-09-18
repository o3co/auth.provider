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
	type AuthorizedFederationGrant,
	DEFAULT_FEDERATION_GRANT_TOMBSTONE_RETENTION_MS,
	type FederationGrant,
	type FederationGrantAuthorization,
	type FederationGrantCredentials,
	type FederationGrantIneligibilityMarker,
	type FederationGrantIneligibilityReason,
	type FederationGrantLockResult,
	type FederationGrantRefreshFailureKind,
	type FederationGrantRevokedBy,
	type FederationGrantStore,
	type FederationGrantWrite,
	withinFederationGrantLifetimeCeiling,
} from "@o3co/auth-provider-core";
import type { FederationGrantHashFields, FederationGrantStoreClient } from "./clients.mjs";
import {
	type FederationGrantKey,
	openSealedCredential,
	sealCredential,
} from "./internal/crypto.mjs";
import {
	type EncryptionGuardContext,
	validateEncryptionMode,
} from "./internal/encryption-mode.mjs";
import {
	canonicalAuthorization,
	credentialAad,
	decodeCredentials,
	encodeCredentials,
	parseCanonicalAuthorization,
} from "./internal/federation-grant-codec.mjs";
import { createFederationGrantLock } from "./internal/federation-grant-lock.mjs";

/**
 * How far past a record's horizon the subject index keeps its member, and how
 * far past the last horizon the index key itself lives: five minutes.
 *
 * The index is a key of its own, in its own slot, so on a Cluster it and the
 * records it points at are on different nodes, reading different clocks. A
 * member dropped while a replica whose clock is behind can still read its
 * record is a record `find` answers for and a listing has lost, so the drop
 * is held back by more than any two nodes in one deployment should disagree.
 * Erring the other way costs a dangling member until the next prune, which is
 * what the layout tolerates by design (D16).
 */
export const DEFAULT_FEDERATION_GRANT_LISTING_ALLOWANCE_MS = 300_000;

/** How many records a listing reads at once. Each is its own key, and on a Cluster its own node. */
const LISTING_CONCURRENCY = 16;

export type { FederationGrantKey };

export type FederationGrantEncryption =
	| { readonly mode: "required"; readonly keys: readonly FederationGrantKey[] }
	| { readonly mode: "allow-plaintext" };

export interface RedisFederationGrantStoreOptions {
	readonly client: FederationGrantStoreClient;
	/** Outer namespace. The hash tag and the `:grant` / `:cred` / `:lock` segments follow it. Default `fg:`. */
	readonly keyPrefix?: string;
	/**
	 * How long a record answers past the end of what it was authorized for
	 * (D16). Taken at creation and kept with the record: a key's TTL and an
	 * index score are set when they are written, so a store reopened under a
	 * different setting must not disagree with the arithmetic it wrote.
	 */
	readonly tombstoneRetentionMs?: number;
	readonly encryption: FederationGrantEncryption;
	/** See {@link DEFAULT_FEDERATION_GRANT_LISTING_ALLOWANCE_MS}. */
	readonly listingAllowanceMs?: number;
	/** What the production guard on `allow-plaintext` reads beside the mode (#473). */
	readonly guard?: EncryptionGuardContext;
}

/** A plaintext credential, under `allow-plaintext`. Its own spelling, so that neither reader takes the other's. */
const PLAINTEXT_PREFIX = "p2.";

const RANGE = (what: string): RangeError => new RangeError(`federation grant store: ${what}`);

/** Every instant a caller passes is refused rather than compared: every comparison with NaN is false. */
const instant = (value: Date, name: string): number => {
	const ms = value?.getTime?.();
	if (typeof ms !== "number" || Number.isNaN(ms)) throw RANGE(`${name} must be a date`);
	return ms;
};

const isDate = (value: unknown): value is Date =>
	value instanceof Date && !Number.isNaN(value.getTime());

/**
 * A key segment that cannot be confused with another value's, and cannot
 * carry a brace into a hash tag. JSON rather than raw UTF-8, so that two IDs
 * differing only in a lone surrogate cannot encode to the same bytes.
 */
const segment = (value: string): string =>
	Buffer.from(JSON.stringify(value), "utf8").toString("base64url");

/**
 * A stored integer, or nothing. Safe integers only: `version` is compared and
 * incremented as a number, and past 2^53 the increment is the same double — a
 * refresh would match the version it had just written, and two of them would
 * both believe they had rotated the token (the reviewer).
 */
const numberFrom = (value: string | undefined): number | undefined => {
	if (value === undefined || !/^-?\d+$/.test(value)) return undefined;
	const parsed = Number(value);
	return Number.isSafeInteger(parsed) ? parsed : undefined;
};

const dateFrom = (value: string | undefined): Date | undefined => {
	const ms = numberFrom(value);
	return ms === undefined ? undefined : new Date(ms);
};

interface BaseFields {
	readonly id: string;
	readonly subject: string;
	readonly clientId: string;
	readonly connection: string;
	readonly createdAt: Date;
}

const parseBase = (text: string | undefined): BaseFields | undefined => {
	if (text === undefined) return undefined;
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		return undefined;
	}
	if (!Array.isArray(parsed) || parsed.length !== 5) return undefined;
	const [id, subject, clientId, connection, createdAtMs] = parsed as unknown[];
	if (
		typeof id !== "string" ||
		typeof subject !== "string" ||
		typeof clientId !== "string" ||
		typeof connection !== "string" ||
		typeof createdAtMs !== "string"
	) {
		return undefined;
	}
	const createdAt = dateFrom(createdAtMs);
	return createdAt === undefined ? undefined : { id, subject, clientId, connection, createdAt };
};

const parseMarker = (text: string | undefined): FederationGrantIneligibilityMarker | undefined => {
	if (text === undefined) return undefined;
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		return undefined;
	}
	if (!Array.isArray(parsed) || parsed.length !== 3) return undefined;
	const [reason, atMs, judgedAgainst] = parsed as unknown[];
	const at = typeof atMs === "string" ? dateFrom(atMs) : undefined;
	if (typeof reason !== "string" || at === undefined || typeof judgedAgainst !== "string") {
		return undefined;
	}
	const against = Number(judgedAgainst);
	if (!Number.isFinite(against)) return undefined;
	return {
		reason: reason as FederationGrantIneligibilityReason,
		at,
		judgedAgainst: against,
	};
};

const encodeMarker = (marker: FederationGrantIneligibilityMarker): string =>
	JSON.stringify([marker.reason, String(marker.at.getTime()), String(marker.judgedAgainst)]);

/** What the record says, and what the record is retained until — the one arithmetic every answer uses. */
interface Decoded {
	readonly grant: FederationGrant;
	/** The instant the record answers nothing from, on the caller's clock. */
	readonly horizonMs: number;
	readonly base: BaseFields;
	/** The retention this record carries: what its own horizon is derived from. */
	readonly retentionMs: number;
	readonly authorization?: FederationGrantAuthorization;
	/** The authorization text as stored, for the credential's authenticated data. */
	readonly authorizationText?: string;
	readonly intent?: { readonly handle: string; readonly expiresAtMs: number };
	/** Whether the fields a script guards on still agree with the authenticated text. */
	readonly guardsAgree: boolean;
}

/**
 * The record as the port describes it, derived from the fields.
 *
 * Judged on the *authenticated* text and never on the arithmetic fields the
 * scripts use: those are outside the envelope, so someone able to write to
 * the keyspace could extend one. Doing that can make a key linger; it cannot
 * make a credential be disclosed past the expiry the upstream consented to.
 */
function decode(
	fields: FederationGrantHashFields,
	/** The ID the record was looked up by. One that says it is another grant is not this grant's. */
	grantId?: string,
): Decoded | undefined {
	if (fields.format !== "1") return undefined;
	const base = parseBase(fields.base);
	const version = numberFrom(fields.version);
	if (base === undefined || version === undefined) return undefined;
	if (grantId !== undefined && base.id !== grantId) return undefined;
	// The retention the record carries, and not the one configured now: a key's
	// TTL and an index score are written once, so the scripts go on using the
	// persisted value, and a horizon read from a changed setting would hide a
	// tombstone whose keys are still there (Codex).
	//
	// A record without it answers NOTHING, rather than falling back to the
	// setting: the field is in neither the envelope nor the guard comparison,
	// and every script derives the horizon from it — so a record whose
	// retention had gone would go on disclosing its credential while every
	// write, a revocation included, was refused for ever. A grant that cannot
	// be ended is the one thing this store may never produce (the reviewer).
	const retentionMs = numberFrom(fields.retentionMs);
	if (retentionMs === undefined) return undefined;
	const status = fields.status;
	const revokedAt = dateFrom(fields.revokedAt);
	const revokedBy = fields.revokedBy;
	const intentExpiresAtMs = numberFrom(fields.intentExpiresAt);
	const intent =
		fields.intentHandle !== undefined && intentExpiresAtMs !== undefined
			? { handle: fields.intentHandle, expiresAtMs: intentExpiresAtMs }
			: undefined;
	const revocation =
		status === "revoked" && revokedAt !== undefined && revokedBy !== undefined
			? {
					status: "revoked" as const,
					revocation: { by: revokedBy as FederationGrantRevokedBy, at: revokedAt },
				}
			: undefined;
	if (status === "revoked" && revocation === undefined) return undefined;

	if (fields.authorization === undefined) {
		// Never authorized: `pending`, or revoked before it ever was.
		if (status !== "pending" && status !== "revoked") return undefined;
		const horizonMs =
			status === "pending"
				? (intentExpiresAtMs ?? Number.NaN)
				: (revokedAt as Date).getTime() + retentionMs;
		const pending = {
			...base,
			version,
			...(status === "pending" ? { status: "pending" as const } : revocation),
		} as FederationGrant;
		return {
			grant: pending,
			horizonMs,
			base,
			retentionMs,
			guardsAgree: true,
			...(intent ? { intent } : {}),
		};
	}

	const authorization = parseCanonicalAuthorization(fields.authorization);
	if (authorization === undefined) return undefined;
	if (status !== "active" && status !== "reauthorization_required" && status !== "revoked") {
		return undefined;
	}
	const lastUsedAt = dateFrom(fields.lastUsedAt);
	const marker = parseMarker(fields.ineligible);
	const failureAt = dateFrom(fields.failureAt);
	const failureCount = numberFrom(fields.failureCount);
	const retryAfterSeconds = fields.failureRetryAfterSeconds;
	const refreshFailure =
		failureAt !== undefined && fields.failureKind !== undefined && failureCount !== undefined
			? {
					at: failureAt,
					kind: fields.failureKind as FederationGrantRefreshFailureKind,
					count: failureCount,
					...(retryAfterSeconds !== undefined && Number.isFinite(Number(retryAfterSeconds))
						? { retryAfterSeconds: Number(retryAfterSeconds) }
						: {}),
					...(fields.failureUpstreamCode !== undefined
						? { upstreamCode: fields.failureUpstreamCode }
						: {}),
				}
			: undefined;
	const grant = {
		...base,
		version,
		...authorization,
		...(lastUsedAt !== undefined ? { lastUsedAt } : {}),
		...(marker !== undefined ? { ineligible: marker } : {}),
		...(refreshFailure !== undefined ? { refreshFailure } : {}),
		...(revocation ?? { status: status as "active" | "reauthorization_required" }),
	} as AuthorizedFederationGrant;
	return {
		grant,
		horizonMs: authorization.expiresAt.getTime() + retentionMs,
		base,
		retentionMs,
		authorization,
		authorizationText: fields.authorization,
		guardsAgree:
			fields.identityRevision === authorization.identityRevision &&
			fields.upstreamIssuer === authorization.upstream.issuer &&
			fields.upstreamSubject === authorization.upstream.subject &&
			numberFrom(fields.expiresAtMs) === authorization.expiresAt.getTime(),
		...(intent ? { intent } : {}),
	};
}

/**
 * The Redis adapter for {@link FederationGrantStore} (#593, D16).
 *
 * Every write is one script and every guard is inside it; this module builds
 * the keys, seals and opens the credential, and derives the record. What it
 * never does is decide a write from a record it read a round trip earlier: a
 * read before a write is preparation — the subject an index is named after,
 * the authorization a credential is sealed under — and the script checks
 * every state it depends on again.
 */
export function createRedisFederationGrantStore(
	options: RedisFederationGrantStoreOptions,
): FederationGrantStore {
	const { client } = options;
	const keyPrefix = options.keyPrefix ?? "fg:";
	if (keyPrefix.includes("{") || keyPrefix.includes("}")) {
		throw new Error('federation grant store: keyPrefix may not contain "{" or "}"');
	}
	const retentionMs =
		options.tombstoneRetentionMs ?? DEFAULT_FEDERATION_GRANT_TOMBSTONE_RETENTION_MS;
	if (!Number.isFinite(retentionMs) || retentionMs < 0) {
		throw new Error(
			"federation grant store: tombstoneRetentionMs must be a non-negative finite number",
		);
	}
	const allowanceMs = options.listingAllowanceMs ?? DEFAULT_FEDERATION_GRANT_LISTING_ALLOWANCE_MS;
	if (!Number.isFinite(allowanceMs) || allowanceMs < 0) {
		throw new Error(
			"federation grant store: listingAllowanceMs must be a non-negative finite number",
		);
	}
	validateEncryptionMode("federation-grants", options.encryption.mode, options.guard ?? {});
	// Copied, so a buffer the caller mutates after construction cannot change
	// what this store opens — the ring is held for the store's whole life.
	const ring: readonly FederationGrantKey[] =
		options.encryption.mode === "required"
			? options.encryption.keys.map((entry) => ({ id: entry.id, key: Buffer.from(entry.key) }))
			: [];
	if (options.encryption.mode === "required") {
		if (ring.length === 0) {
			throw new Error('federation grant store: mode "required" needs at least one encryption key');
		}
		// Refused here rather than at the first write: a ring that cannot seal is
		// a configuration problem, and finding it out per grant means finding it
		// out once a user has already consented.
		sealCredential("", ring, Buffer.alloc(0));
	}

	const grantKey = (id: string): string => `${keyPrefix}{${segment(id)}}:grant`;
	const credKey = (id: string): string => `${keyPrefix}{${segment(id)}}:cred`;
	const lockKey = (id: string): string => `${keyPrefix}{${segment(id)}}:lock`;
	const indexKey = (subject: string): string => `${keyPrefix}sub:${segment(subject)}`;
	const member = (id: string): string => segment(id);

	const lock = createFederationGrantLock({ client, lockKey });

	const aadFor = (decoded: Decoded, authorizationText: string, grantId: string): Buffer =>
		credentialAad({
			// The key this credential was READ from, never one rebuilt from what
			// the record says its ID is: a HASH copied together with its
			// ciphertext into another grant's keys would otherwise authenticate
			// under the name it carries (Codex).
			credentialKey: credKey(grantId),
			id: decoded.base.id,
			subject: decoded.base.subject,
			clientId: decoded.base.clientId,
			connection: decoded.base.connection,
			authorization: authorizationText,
		});

	const seal = (
		credentials: FederationGrantCredentials,
		binding: {
			id: string;
			subject: string;
			clientId: string;
			connection: string;
			authorization: string;
		},
	): string => {
		const payload = encodeCredentials(credentials);
		if (options.encryption.mode === "allow-plaintext") {
			return PLAINTEXT_PREFIX + Buffer.from(payload, "utf8").toString("base64url");
		}
		return sealCredential(
			payload,
			ring,
			credentialAad({ credentialKey: credKey(binding.id), ...binding }),
		);
	};

	/** What `open` and `inspect` say about the credential they read beside the record. */
	const openCredential = (
		decoded: Decoded,
		credential: string | null,
		nowMs: number,
		grantId: string,
	):
		| { state: "ok"; value: FederationGrantCredentials }
		| { state: "absent" | "unreadable" | "key_unavailable" } => {
		// Only an `active` grant has one, and none from the stored expiry on —
		// the status is checked as well, so a transition that forgot to delete a
		// credential would still disclose nothing.
		if (decoded.grant.status !== "active") return { state: "absent" };
		const authorization = decoded.authorization;
		if (authorization === undefined) return { state: "absent" };
		if (!(nowMs < authorization.expiresAt.getTime())) return { state: "absent" };
		if (credential === null) return { state: "absent" };
		// A guard field that no longer agrees with the text it was copied from
		// means the keyspace was written by something else. The text is
		// authoritative, so the credential would still authenticate — and a
		// record in that state is not one to hand a credential out of.
		if (!decoded.guardsAgree) return { state: "unreadable" };
		const text = decoded.authorizationText as string;
		let payload: string;
		if (options.encryption.mode === "allow-plaintext") {
			if (!credential.startsWith(PLAINTEXT_PREFIX)) return { state: "unreadable" };
			payload = Buffer.from(credential.slice(PLAINTEXT_PREFIX.length), "base64url").toString(
				"utf8",
			);
		} else {
			const opened = openSealedCredential(credential, ring, aadFor(decoded, text, grantId));
			if (opened.state !== "ok") return { state: opened.state };
			payload = opened.value;
		}
		const credentials = decodeCredentials(payload);
		return credentials === undefined
			? { state: "unreadable" }
			: { state: "ok", value: credentials };
	};

	const visible = (decoded: Decoded | undefined, nowMs: number): Decoded | undefined =>
		decoded !== undefined && nowMs < decoded.horizonMs ? decoded : undefined;

	const read = async (
		grantId: string,
		nowMs: number,
	): Promise<{ decoded: Decoded; credential: string | null } | null> => {
		const snapshot = await client.snapshot(grantKey(grantId), credKey(grantId));
		if (snapshot === null) return null;
		const decoded = visible(decode(snapshot.fields, grantId), nowMs);
		return decoded === undefined ? null : { decoded, credential: snapshot.credential };
	};

	const written = (
		fields: FederationGrantHashFields | null,
		grantId: string,
	): FederationGrantWrite => {
		if (fields === null) return { ok: false };
		const decoded = decode(fields, grantId);
		return decoded === undefined ? { ok: false } : { ok: true, grant: decoded.grant };
	};

	/** The horizon a record will have once it is written, which is what its index member is reserved at. */
	const horizonOf = (
		status: "pending" | "authorized" | "revoked",
		ms: number,
		recordRetentionMs = retentionMs,
	): number => (status === "pending" ? ms : ms + recordRetentionMs);

	return {
		kind: "redis",

		async createPending(input) {
			const nowMs = instant(input.now, "now");
			// An intent whose expiry is not a date creates nothing, and does not
			// throw: only the caller's own clock is refused that way, and
			// `nowMs < NaN` is false in either adapter.
			if (!isDate(input.intent.expiresAt)) return { ok: false };
			const intentExpiresAtMs = input.intent.expiresAt.getTime();
			// The member goes in before the record, at the horizon the record will
			// have, so a prune in between sees a score that is not due (D16).
			await client.reserve(
				indexKey(input.subject),
				member(input.id),
				horizonOf("pending", intentExpiresAtMs),
				allowanceMs,
			);
			return written(
				await client.createPending(grantKey(input.id), credKey(input.id), {
					nowMs,
					base: JSON.stringify([
						input.id,
						input.subject,
						input.clientId,
						input.connection,
						String(nowMs),
					]),
					handle: input.intent.handle,
					intentExpiresAtMs,
					retentionMs,
				}),
				input.id,
			);
		},

		async nameIntent(input) {
			const nowMs = instant(input.now, "now");
			if (!isDate(input.intent.expiresAt)) return { ok: false };
			// A round trip this write would not otherwise need, for the reason
			// `activate` takes one: naming an intent is where a renewal starts,
			// and the script decides it from the copies. The pointer is worth
			// nothing on its own, but an activation follows it.
			const before = await client.snapshot(grantKey(input.grantId), credKey(input.grantId));
			if (before === null) return { ok: false };
			const current = decode(before.fields, input.grantId);
			if (current === undefined || !current.guardsAgree) return { ok: false };
			return written(
				await client.nameIntent(grantKey(input.grantId), {
					nowMs,
					handle: input.intent.handle,
					intentExpiresAtMs: input.intent.expiresAt.getTime(),
				}),
				input.grantId,
			);
		},

		async isCurrentIntent(grantId, handle, now) {
			const nowMs = instant(now, "now");
			const found = await read(grantId, nowMs);
			if (found === null) return false;
			const { decoded } = found;
			if (decoded.grant.status === "revoked") return false;
			// The STORED expiry: a new consent must not resurrect a grant whose
			// consented lifetime has ended. "Unless pending" — not "if active".
			if (
				decoded.grant.status !== "pending" &&
				!(nowMs < (decoded.authorization?.expiresAt.getTime() ?? Number.NaN))
			) {
				return false;
			}
			return (
				decoded.intent !== undefined &&
				decoded.intent.handle === handle &&
				nowMs < decoded.intent.expiresAtMs
			);
		},

		async retireIntent(input) {
			return written(
				await client.retireIntent(grantKey(input.grantId), {
					nowMs: instant(input.now, "now"),
					...(input.handle !== undefined ? { handle: input.handle } : {}),
				}),
				input.grantId,
			);
		},

		async find(grantId, now) {
			const found = await read(grantId, instant(now, "now"));
			return found === null ? null : found.decoded.grant;
		},

		async listBySubject(subject, now) {
			const nowMs = instant(now, "now");
			const key = indexKey(subject);
			// On the adapter's own clock, as a key TTL is — never the caller's.
			await client.prune(key, Date.now(), allowanceMs);
			const members = await client.members(key);
			const found: FederationGrant[] = [];
			for (let i = 0; i < members.length; i += LISTING_CONCURRENCY) {
				const batch = members.slice(i, i + LISTING_CONCURRENCY);
				const read = await Promise.all(
					batch.map(async (entry) => {
						let id: unknown;
						try {
							id = JSON.parse(Buffer.from(entry, "base64url").toString("utf8"));
						} catch {
							return null;
						}
						if (typeof id !== "string") return null;
						const snapshot = await client.snapshot(grantKey(id), credKey(id));
						return snapshot === null ? null : (decode(snapshot.fields, id) ?? null);
					}),
				);
				for (const decoded of read) {
					// The subject is compared on the record and not taken from the
					// index: an ID can be reused, and a dangling member would
					// otherwise hand one subject another's grant.
					if (decoded !== null && decoded.base.subject === subject) {
						const live = visible(decoded, nowMs);
						if (live !== undefined) found.push(live.grant);
					}
				}
			}
			return found;
		},

		async inspect(grantId, now) {
			const nowMs = instant(now, "now");
			const found = await read(grantId, nowMs);
			if (found === null) return null;
			const opened = openCredential(found.decoded, found.credential, nowMs, grantId);
			return { grant: found.decoded.grant, credentials: opened.state };
		},

		async open(grantId, now) {
			const nowMs = instant(now, "now");
			const found = await read(grantId, nowMs);
			if (found === null) return null;
			const opened = openCredential(found.decoded, found.credential, nowMs, grantId);
			return {
				grant: found.decoded.grant,
				credentials:
					opened.state === "ok" ? { state: "ok", value: opened.value } : { state: opened.state },
			};
		},

		async activate(input) {
			const nowMs = instant(input.now, "now");
			const authorization = input.authorization;
			// Everything that depends only on the input, before anything is
			// written: a refusal leaves the grant exactly as it was (D7).
			if (!isDate(authorization.expiresAt) || !(nowMs < authorization.expiresAt.getTime())) {
				return { ok: false };
			}
			if (!isDate(authorization.consent.at) || !isDate(authorization.authorizedAt)) {
				return { ok: false };
			}
			if (
				!withinFederationGrantLifetimeCeiling(authorization.consent.at, authorization.expiresAt)
			) {
				return { ok: false };
			}
			// Not dated after this write, with no allowance: a revocation boundary
			// stamped from now on must always cover the consent (D13).
			if (!(authorization.consent.at.getTime() <= nowMs)) return { ok: false };
			if (!(authorization.authorizedAt.getTime() <= nowMs)) return { ok: false };
			if (!isDate(authorization.expiresAt)) return { ok: false };
			const access = input.credentials.accessToken;
			if (access !== undefined && !isDate(access.obtainedAt)) return { ok: false };

			// Preparation, not authority: the subject names the index, and the
			// record is what the credential is sealed against. The script checks
			// every state again.
			const snapshot = await client.snapshot(grantKey(input.grantId), credKey(input.grantId));
			if (snapshot === null) return { ok: false };
			const current = decode(snapshot.fields, input.grantId);
			if (current === undefined) return { ok: false };
			// The scripts compare the copies, so a copy rewritten in the keyspace
			// would let a write through that was refused before it: one `HSET` of
			// the expiry renews a grant whose consented lifetime had ended, and
			// one of the upstream account re-points it (the reviewer). Where a
			// write has a snapshot in hand, the copies must still agree with the
			// text the credential was sealed under.
			if (!current.guardsAgree) return { ok: false };
			const text = canonicalAuthorization(authorization);
			const credential = seal(input.credentials, {
				id: current.base.id,
				subject: current.base.subject,
				clientId: current.base.clientId,
				connection: current.base.connection,
				authorization: text,
			});
			await client.reserve(
				indexKey(current.base.subject),
				member(current.base.id),
				horizonOf("authorized", authorization.expiresAt.getTime(), current.retentionMs),
				allowanceMs,
			);
			return written(
				await client.activate(grantKey(input.grantId), credKey(input.grantId), {
					nowMs,
					handle: input.intentHandle,
					authorization: text,
					expiresAtMs: authorization.expiresAt.getTime(),
					identityRevision: authorization.identityRevision,
					upstreamIssuer: authorization.upstream.issuer,
					upstreamSubject: authorization.upstream.subject,
					credential,
				}),
				input.grantId,
			);
		},

		async replaceCredentials(input) {
			const nowMs = instant(input.now, "now");
			const access = input.credentials.accessToken;
			if (access !== undefined && !isDate(access.obtainedAt)) return { ok: false };
			if (input.ineligible !== null && !isDate(input.ineligible.at)) return { ok: false };
			const snapshot = await client.snapshot(grantKey(input.grantId), credKey(input.grantId));
			if (snapshot === null) return { ok: false };
			const current = decode(snapshot.fields, input.grantId);
			if (current === undefined || current.authorizationText === undefined) return { ok: false };
			if (!current.guardsAgree) return { ok: false };
			// The authorization this seals under must be the one the credential it
			// replaces was sealed under. Otherwise a rewritten authorization —
			// the expiry extended, the version left alone — would be turned by
			// this write into one the store had signed for, and tampering that
			// was being reported as unreadable would become authentic (Codex).
			if (openCredential(current, snapshot.credential, nowMs, input.grantId).state !== "ok") {
				return { ok: false };
			}
			const credential = seal(input.credentials, {
				id: current.base.id,
				subject: current.base.subject,
				clientId: current.base.clientId,
				connection: current.base.connection,
				authorization: current.authorizationText,
			});
			return written(
				await client.replaceCredentials(grantKey(input.grantId), credKey(input.grantId), {
					nowMs,
					expectedVersion: input.expectedVersion,
					credential,
					ineligible: input.ineligible === null ? null : encodeMarker(input.ineligible),
				}),
				input.grantId,
			);
		},

		async requireReauthorization(input) {
			return written(
				await client.requireReauthorization(grantKey(input.grantId), credKey(input.grantId), {
					nowMs: instant(input.now, "now"),
					expectedVersion: input.expectedVersion,
				}),
				input.grantId,
			);
		},

		async revoke(grantId, by, at) {
			const atMs = instant(at, "at");
			// A grant revoked before it was ever authorized is retained from the
			// revocation, so its horizon moves forward and its member must be
			// reserved at the new one before the record says so.
			// Read for the subject the index is named after, and for nothing
			// else: this write has no version to match and the port has it
			// always win, so a record this adapter cannot decode is still
			// revoked — that is exactly the state an operator needs to end, and
			// its credential is still at rest beside it (the reviewer).
			const snapshot = await client.snapshot(grantKey(grantId), credKey(grantId));
			const current = snapshot === null ? undefined : decode(snapshot.fields, grantId);
			if (current !== undefined && current.grant.status === "pending") {
				await client.reserve(
					indexKey(current.base.subject),
					member(current.base.id),
					horizonOf("revoked", atMs, current.retentionMs),
					allowanceMs,
				);
			}
			return written(
				await client.revoke(grantKey(grantId), credKey(grantId), { atMs, by }),
				grantId,
			);
		},

		async noteRefreshFailure(input) {
			const nowMs = instant(input.now, "now");
			if (!isDate(input.failure.at)) return { ok: false };
			return written(
				await client.noteRefreshFailure(grantKey(input.grantId), {
					nowMs,
					expectedVersion: input.expectedVersion,
					atMs: input.failure.at.getTime(),
					kind: input.failure.kind,
					rowMs: input.rowMs,
					...(input.failure.retryAfterSeconds !== undefined
						? { retryAfterSeconds: input.failure.retryAfterSeconds }
						: {}),
					...(input.failure.upstreamCode !== undefined
						? { upstreamCode: input.failure.upstreamCode }
						: {}),
				}),
				input.grantId,
			);
		},

		async touch(grantId, at) {
			const atMs = at?.getTime?.();
			if (typeof atMs !== "number" || Number.isNaN(atMs)) return;
			await client.touch(grantKey(grantId), atMs);
		},

		async acquireRefreshLock(grantId, bounds): Promise<FederationGrantLockResult> {
			return await lock.acquire(grantId, bounds);
		},
	};
}
