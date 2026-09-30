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
	checkDeploymentMode,
	checkSealingKeyRing,
	constantTimeStringEqual,
	DEFAULT_FEDERATION_GRANT_TOMBSTONE_RETENTION_MS,
	type DeploymentMode,
	decodeSealingKey,
	defineModule,
	type FederationGrant,
	type FederationGrantAuthorization,
	type FederationGrantCredentials,
	type FederationGrantIneligibilityMarker,
	type FederationGrantIneligibilityReason,
	type FederationGrantLockResult,
	type FederationGrantRefreshFailureKind,
	type FederationGrantRevokedBy,
	type FederationGrantStore,
	type FederationGrantUsage,
	type FederationGrantWrite,
	isStorableLifetime,
	MAX_DURATION_MS,
	MAX_DURATION_SECONDS,
	type PendingFederationGrant,
	type RevokedFederationGrant,
	SEALING_KEY_BYTES,
	withinFederationGrantLifetimeCeiling,
} from "@o3co/auth-provider-core";
import { z } from "zod";
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
 * The index is a key in its own slot, so on a Cluster it and the records it
 * points at are on different nodes, reading different clocks. A member
 * dropped while a replica whose clock is behind can still read its record is
 * a record `find` answers for and a listing has lost, so the drop is held
 * back by more than any two nodes in one deployment should disagree. Erring
 * the other way costs a dangling member until the next prune, which the
 * layout tolerates by design.
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
	 * How long a record answers past the end of what it was authorized for.
	 * Taken at creation and kept with the record: a key's TTL and an
	 * index score are set when they are written, so a store reopened under a
	 * different setting must not disagree with the arithmetic it wrote.
	 */
	readonly tombstoneRetentionMs?: number;
	readonly encryption: FederationGrantEncryption;
	/** See {@link DEFAULT_FEDERATION_GRANT_LISTING_ALLOWANCE_MS}. */
	readonly listingAllowanceMs?: number;
	/** What the production guard on `allow-plaintext` reads beside the mode. */
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
 * Whether the credentials are ones this store can keep: the access token's
 * date is a date, and its issued lifetime a finite number. Sealed, a lifetime
 * of NaN or infinity reads back as an unreadable credential, and every refresh
 * after it is refused; refused at the write instead, as every adapter refuses
 * it.
 */
const storableCredentials = (credentials: FederationGrantCredentials): boolean =>
	credentials.accessToken === undefined ||
	(isDate(credentials.accessToken.obtainedAt) &&
		Number.isFinite(credentials.accessToken.issuedLifetime));

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
 * both believe they had rotated the token.
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
	// The retention the record carries, not the one configured now: a key's
	// TTL and an index score are written once, and a horizon read from a
	// changed setting would hide a tombstone whose keys are still there.
	//
	// A record without it answers NOTHING, rather than falling back to the
	// setting: the field is in neither the envelope nor the guard comparison,
	// and every script derives the horizon from it, so such a record would go
	// on disclosing its credential while every write, a revocation included,
	// was refused for ever. A grant that cannot be ended is the one thing this
	// store may never produce.
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
		// Annotated rather than cast: a base field this read forgot is a compile
		// error. `revocation` is defined exactly when the status is `revoked`,
		// which the checks above established.
		const pending: PendingFederationGrant | RevokedFederationGrant =
			revocation === undefined
				? { ...base, version, status: "pending" }
				: { ...base, version, ...revocation };
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
	const failureAt = dateFrom(fields.failureAt);
	const failureCount = numberFrom(fields.failureCount);
	const retryAfterSeconds = fields.failureRetryAfterSeconds;
	// Typed literals, each field named: a HASH field this read forgot is a
	// compile error, where a spread of conditional parts and a cast of the
	// whole to the grant type would let one go without a sound.
	const usage: FederationGrantUsage = {
		lastUsedAt: dateFrom(fields.lastUsedAt),
		ineligible: parseMarker(fields.ineligible),
		refreshFailure:
			failureAt !== undefined && fields.failureKind !== undefined && failureCount !== undefined
				? {
						at: failureAt,
						kind: fields.failureKind as FederationGrantRefreshFailureKind,
						retryAfterSeconds:
							retryAfterSeconds !== undefined && Number.isFinite(Number(retryAfterSeconds))
								? Number(retryAfterSeconds)
								: undefined,
						upstreamCode: fields.failureUpstreamCode,
						count: failureCount,
					}
				: undefined,
	};
	const grant: AuthorizedFederationGrant | RevokedFederationGrant =
		revocation === undefined
			? {
					...base,
					version,
					...authorization,
					...usage,
					status: status as "active" | "reauthorization_required",
				}
			: { ...base, version, ...authorization, ...usage, ...revocation };
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
 * The Redis adapter for {@link FederationGrantStore}. See ADR
 * 2026-09-17-federation-grants-offline-delegation, D16.
 *
 * Every write is one script and every guard is inside it; this module builds
 * the keys, seals and opens the credential, and derives the record. It never
 * decides a write from a record read a round trip earlier: a read before a
 * write is preparation — the subject an index is named after, the
 * authorization a credential is sealed under — and the script checks every
 * state it depends on again.
 */
export function createRedisFederationGrantStore(
	options: RedisFederationGrantStoreOptions,
): FederationGrantStore {
	const { client } = options;
	const keyPrefix = options.keyPrefix ?? "fg:";
	// A brace would move the hash tag a grant's three keys share. Refused as a
	// RangeError, as every setting this store is given and cannot use is.
	if (keyPrefix.includes("{") || keyPrefix.includes("}")) {
		throw RANGE('keyPrefix may not contain "{" or "}"');
	}
	// Both must end within the Date range (core's `isStorableLifetime`). The
	// scripts write a record or its subject-index entry and set the key's
	// deadline last, so a deadline Redis refuses leaves what was written with no
	// TTL; and a retention past 2^53 is written into a record that then does
	// not read back, so every lodging fails and leaves its record behind. A
	// RangeError, as the in-process store and the shared expiry rule refuse
	// a lifetime.
	const retentionMs =
		options.tombstoneRetentionMs ?? DEFAULT_FEDERATION_GRANT_TOMBSTONE_RETENTION_MS;
	if (!isStorableLifetime(retentionMs, { allowZero: true })) {
		throw new RangeError(
			"federation grant store: tombstoneRetentionMs must be a non-negative number of milliseconds that ends within the Date range",
		);
	}
	const allowanceMs = options.listingAllowanceMs ?? DEFAULT_FEDERATION_GRANT_LISTING_ALLOWANCE_MS;
	if (!isStorableLifetime(allowanceMs, { allowZero: true })) {
		throw new RangeError(
			"federation grant store: listingAllowanceMs must be a non-negative number of milliseconds that ends within the Date range",
		);
	}
	validateEncryptionMode("federation-grants", options.encryption.mode, options.guard ?? {});
	// Copied, so a buffer the caller mutates after construction cannot change
	// what this store opens — the ring is held for the store's whole life.
	if (options.encryption.mode === "required") {
		// A ring is a setting: every refusal of it, here or in core's ring rule,
		// is a RangeError. Refused here rather than at the first write: a ring
		// that cannot seal is a configuration problem, and finding it out per
		// grant means finding it out once a user has already consented. Checked
		// as it was handed over, before the copy below: `Buffer.from` would turn
		// a string key into its UTF-8 bytes.
		if (options.encryption.keys.length === 0) {
			throw RANGE('mode "required" needs at least one encryption key');
		}
		checkSealingKeyRing(options.encryption.keys, "federation grant store: encryption.keys");
	}
	const ring: readonly FederationGrantKey[] =
		options.encryption.mode === "required"
			? options.encryption.keys.map((entry) => ({ id: entry.id, key: Buffer.from(entry.key) }))
			: [];

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
			// under the name it carries.
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
			// have, so a prune in between sees a score that is not due.
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
			// In constant time, as the reference adapter and the scripts' `fg_same`
			// compare it: the handle is a capability the browser carries.
			return (
				decoded.intent !== undefined &&
				constantTimeStringEqual(decoded.intent.handle, handle) &&
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
			// written: a refusal leaves the grant exactly as it was.
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
			// stamped from now on must always cover the consent.
			if (!(authorization.consent.at.getTime() <= nowMs)) return { ok: false };
			if (!(authorization.authorizedAt.getTime() <= nowMs)) return { ok: false };
			if (!isDate(authorization.expiresAt)) return { ok: false };
			if (!storableCredentials(input.credentials)) return { ok: false };

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
			// one of the upstream account re-points it. Where a
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
			// A version that is not a whole number is not one a caller read. The
			// client writes a number out as an integer and the script compares
			// numbers, so a fractional version would round into a match.
			if (!Number.isSafeInteger(input.expectedVersion)) return { ok: false };
			if (!storableCredentials(input.credentials)) return { ok: false };
			if (input.ineligible !== null && !isDate(input.ineligible.at)) return { ok: false };
			// Read back, a marker judged against a maximum that is not finite is no
			// marker at all: refused here, as every adapter refuses it.
			if (input.ineligible !== null && !Number.isFinite(input.ineligible.judgedAgainst)) {
				return { ok: false };
			}
			const snapshot = await client.snapshot(grantKey(input.grantId), credKey(input.grantId));
			if (snapshot === null) return { ok: false };
			const current = decode(snapshot.fields, input.grantId);
			if (current === undefined || current.authorizationText === undefined) return { ok: false };
			if (!current.guardsAgree) return { ok: false };
			// The authorization this seals under must be the one the credential it
			// replaces was sealed under. Otherwise a rewritten authorization —
			// the expiry extended, the version left alone — would be turned by
			// this write into one the store had signed for, and tampering that
			// was being reported as unreadable would become authentic.
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
			const nowMs = instant(input.now, "now");
			// As in `replaceCredentials`: a fractional version would round into a match.
			if (!Number.isSafeInteger(input.expectedVersion)) return { ok: false };
			return written(
				await client.requireReauthorization(grantKey(input.grantId), credKey(input.grantId), {
					nowMs,
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
			// its credential is still at rest beside it.
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
			// As in `replaceCredentials`: a fractional version would round into a match.
			if (!Number.isSafeInteger(input.expectedVersion)) return { ok: false };
			if (!isDate(input.failure.at)) return { ok: false };
			// Read back, a backoff that is not finite is none: refused here, as
			// every adapter refuses it.
			const retryAfter = input.failure.retryAfterSeconds;
			if (retryAfter !== undefined && !Number.isFinite(retryAfter)) return { ok: false };
			return written(
				await client.noteRefreshFailure(grantKey(input.grantId), {
					nowMs,
					expectedVersion: input.expectedVersion,
					atMs: input.failure.at.getTime(),
					kind: input.failure.kind,
					// In whole milliseconds, as the instants it is compared with are.
					// The client writes a number out as an integer, and a window
					// rounded UP would count as a row two stamps further apart than
					// it.
					rowMs: Math.floor(input.rowMs),
					retryAfterSeconds: input.failure.retryAfterSeconds,
					upstreamCode: input.failure.upstreamCode,
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

// --- configuration --------------------------------------------------------

/**
 * A duration an operator wrote, read strictly: `z.coerce.number()` reads
 * `null` and `[]` as `0`, `true` as `1` and `"1e3"` as `1000`, so
 * `tombstoneRetention: null` would silently mean "keep no tombstones". This
 * module resolves the store independently of core's strict reader, so it
 * needs the rule itself.
 */
const durationFromEnv = (bounds: z.ZodNumber) =>
	z.preprocess((value) => {
		if (typeof value === "number") return value;
		if (typeof value === "string" && /^\d+$/.test(value.trim())) return Number(value.trim());
		return value;
	}, bounds);

/**
 * The `federationGrants` block this store reads, and the
 * `redisFederationGrantStore` one beside it. Two sections because what a
 * grant is allowed to be — its retention, its key ring — is grant policy,
 * set whether the store is Redis or not, while a key prefix and a listing
 * allowance are this adapter's layout. Durations are whole seconds in the
 * policy block and milliseconds where the adapter takes them.
 */
const moduleConfigSchema = z.object({
	federationGrants: z
		.object({
			// One year at most, as core's schema holds every duration an
			// operator writes; the store's constructor is the second line.
			tombstoneRetention: durationFromEnv(
				z.number().int().nonnegative().max(MAX_DURATION_SECONDS),
			).optional(),
			encryptionMode: z.enum(["required", "allow-plaintext"]).optional(),
			encryptionKeys: z
				.array(z.object({ id: z.string().min(1), key: z.string().min(1) }))
				.optional(),
		})
		.default({}),
	redisFederationGrantStore: z
		.object({
			keyPrefix: z.string().default("fg:"),
			listingAllowanceMs: durationFromEnv(
				z.number().int().nonnegative().max(MAX_DURATION_MS),
			).optional(),
		})
		.default({ keyPrefix: "fg:" }),
});

/** What a composition root tells the module that its configuration cannot. */
export interface RedisFederationGrantStoreModuleOptions {
	/** The environment the configuration was selected by, when the root knows it by another name than `NODE_ENV`. */
	readonly environment?: string;
}

/** Where the resolver reads the ring, which is what its refusals name. */
const KEYS_SETTING = "federationGrants.encryptionKeys";

/**
 * Canonical base64 of exactly 32 bytes, or a RangeError that names the entry
 * by its index: core's rule for a configured sealing key
 * (`decodeSealingKey`), applied at boot so that a key that cannot be read is
 * found before a user consents, not per grant after. The entry's id is not
 * quoted: it has not been checked yet, and an operator who swapped an id and
 * its key would see the key in the boot error.
 */
const keyMaterial = (index: number, encoded: string): Buffer => {
	const bytes = decodeSealingKey(encoded);
	if (bytes === undefined) {
		throw RANGE(
			`${KEYS_SETTING}[${index}].key must be canonical base64 of ${SEALING_KEY_BYTES} bytes`,
		);
	}
	return bytes;
};

/**
 * The options the adapter takes, from the configuration an operator wrote,
 * and the replica count `deploymentMode` — the `deploymentMode` slot's value,
 * or `deploymentModeOf(config)` from `@o3co/auth-provider-core` for a
 * composition root that builds the store itself — which the plaintext guard
 * refuses plaintext under when it is `multi`. The configuration's own
 * `deployment` is not read, and a mode that is not `single`, `multi` or
 * `unset` — none included — is a TypeError: read as none, it would let
 * plaintext through under `multi`.
 *
 * A function of its own, and exported, because the conversion is where a
 * module goes wrong silently: seconds forwarded as milliseconds keep a
 * tombstone for thirty seconds instead of thirty days, and a `0` read as
 * "unset" gives a deployment that wanted no tombstones the default thirty
 * days of them.
 */
export function resolveRedisFederationGrantStoreOptions(
	rawConfig: unknown,
	moduleOptions: RedisFederationGrantStoreModuleOptions,
	deploymentMode: DeploymentMode,
): Omit<RedisFederationGrantStoreOptions, "client"> {
	const replicas = checkDeploymentMode(
		deploymentMode,
		"resolveRedisFederationGrantStoreOptions: deploymentMode",
	);
	const config = moduleConfigSchema.parse(rawConfig);
	const grants = config.federationGrants;
	const mode = grants.encryptionMode ?? "required";
	// In the order they were written: the first seals. Checked here, under
	// the key they were read from, before the store checks them again under
	// the option it takes them as.
	const keys: readonly FederationGrantKey[] =
		mode === "allow-plaintext"
			? []
			: (grants.encryptionKeys ?? []).map((entry, index) => ({
					id: entry.id,
					key: keyMaterial(index, entry.key),
				}));
	checkSealingKeyRing(keys, `federation grant store: ${KEYS_SETTING}`);
	return {
		keyPrefix: config.redisFederationGrantStore.keyPrefix,
		...(grants.tombstoneRetention !== undefined
			? { tombstoneRetentionMs: grants.tombstoneRetention * 1000 }
			: {}),
		...(config.redisFederationGrantStore.listingAllowanceMs !== undefined
			? { listingAllowanceMs: config.redisFederationGrantStore.listingAllowanceMs }
			: {}),
		encryption:
			mode === "allow-plaintext" ? { mode: "allow-plaintext" } : { mode: "required", keys },
		guard: {
			...(moduleOptions.environment !== undefined
				? { environment: moduleOptions.environment }
				: {}),
			deploymentMode: replicas,
		},
	};
}

/**
 * `defineModule` manifest for the Redis federation grant store. Its own
 * module, not a branch of the route package's, because a deployment installs
 * the store whether or not it mounts the routes — `revokeAllForSubject` and
 * a logout reach grants through the port.
 *
 * The plaintext guard reads the replica count from the `deploymentMode` slot
 * core fills — required, since `multi` refuses plaintext — and the selected
 * environment off `options`: the module cannot know how a composition root
 * chose its configuration file. Its notice goes to the optional `logger`
 * slot.
 */
export function redisFederationGrantStoreModuleFor(
	options: RedisFederationGrantStoreModuleOptions = {},
) {
	return defineModule({
		name: "redis-federation-grant-store",
		requires: ["federationGrantStoreClient", "config", "deploymentMode"] as const,
		optional: ["logger"] as const,
		configSchema: moduleConfigSchema,
		provides: {
			federationGrantStore: (deps) => {
				const resolved = resolveRedisFederationGrantStoreOptions(
					deps.config,
					options,
					deps.deploymentMode,
				);
				return createRedisFederationGrantStore({
					client: deps.federationGrantStoreClient,
					...resolved,
					guard: {
						...resolved.guard,
						...(deps.logger !== undefined ? { logger: deps.logger } : {}),
					},
				});
			},
		},
	});
}

/**
 * The module with no environment named: the plaintext guard reads `NODE_ENV`
 * and the `deploymentMode` slot. A composition root that selects its
 * configuration by another name builds its own with
 * {@link redisFederationGrantStoreModuleFor}.
 */
export const redisFederationGrantStoreModule = redisFederationGrantStoreModuleFor();
