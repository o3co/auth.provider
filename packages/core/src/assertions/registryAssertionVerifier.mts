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

import { createLocalJWKSet, decodeJwt, errors, type JWTPayload, jwtVerify } from "jose";
import { parseScopeTokens } from "../federations/scope.mjs";
import { malformedNumericDateClaim } from "../jwt/numericDate.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { isRecordableJti } from "../replay-seen-set/jti.mjs";
import type { ReplaySeenSet } from "../replay-seen-set/types.mjs";
import { isWellFormedIdentifier } from "../security/identifier.mjs";
import type { AssertionIssuerEntry, AssertionIssuerRegistry } from "./issuerRegistry.mjs";
import {
	assertionLifetime,
	describeInvalidAssertionClockTolerance,
	isValidAssertionClockTolerance,
	MAX_ASSERTION_LIFETIME_SECONDS,
} from "./lifetime.mjs";
import { createRemoteKeySetCache } from "./remoteKeySet.mjs";
import type {
	AssertionVerificationContext,
	AssertionVerificationResult,
	AssertionVerifier,
} from "./types.mjs";

/** The `typ` an Identity Assertion JWT Authorization Grant MUST carry (ID-JAG §3). */
export const ID_JAG_TYP = "oauth-id-jag+jwt";

export interface RegistryAssertionVerifierOptions {
	readonly registry: AssertionIssuerRegistry;
	/**
	 * What an RFC 7523 assertion's `aud` must name — this authorization server.
	 * RFC 7523 §3 requires the AS to reject an assertion not addressed to it,
	 * and the reason is concrete: without it, an assertion minted for a
	 * *different* service is replayable here. Several values are accepted so a
	 * deployment can name both its issuer identifier and its token endpoint URL.
	 */
	readonly audience: string | readonly string[];
	/**
	 * This authorization server's issuer identifier (RFC 8414) — the one and
	 * only `aud` an ID-JAG may name. Required by any entry whose `profile` is
	 * `"id-jag"`; the token endpoint URL is not an alias there.
	 */
	readonly issuerIdentifier?: string;
	/**
	 * Where ID-JAG `jti` values are recorded so each assertion is accepted once,
	 * keyed per issuer and expiring with the assertion. Required by any
	 * `"id-jag"` entry; a store outage throws, so the grant answers `503` rather
	 * than accepting a replay.
	 */
	readonly replaySeenSet?: ReplaySeenSet;
	/** Adapter kind, for logs and boot diagnostics. Default `"jwt-registry"`. */
	readonly kind?: string;
	/** The fetch a `jwks_uri` entry's key set uses. An egress proxy, or a test seam. */
	readonly fetch?: typeof fetch;
	/**
	 * Where a refusal says why: the grant answers every refusal with the same
	 * `invalid_grant`. Logged at warn as `jwt_bearer_assertion_refused` with the
	 * entry's `issuer` and a `reason`: `lifetime` (with `lifetimeSeconds` and
	 * `maxLifetimeSeconds`) or `numeric_date` (with the `claim`); without an
	 * `issuer`, `malformed_issuer` for an `iss` that cannot name one (the
	 * client's value is not logged). Other refusals are not logged.
	 */
	readonly logger?: Logger;
	/**
	 * How an entry's claims are read (code, so it is not stored on the entry).
	 * Called per verification, ID-JAG entries included; `undefined` or an absent
	 * reader keeps the default: a non-empty `sub` (`<iss>#<sub>` /
	 * `<iss>#<tenant>#<sub>` for an ID-JAG) and a space-delimited `scope`.
	 *
	 * When issuers' `sub` values may collide, namespace the handle for the
	 * entries that need it, and refuse a missing or empty `sub` rather than
	 * namespacing it: the Store receives the handle alone.
	 */
	readonly readersFor?: (entry: AssertionIssuerEntry) => AssertionClaimReaders | undefined;
}

/** How a verifier reads the subject handle and the scope ceiling from an issuer's claims. */
export interface AssertionClaimReaders {
	/** The handle the Store resolves; `null` refuses the assertion. */
	readonly readSubjectHandle?: (claims: JWTPayload) => string | null;
	/** The scope the assertion claims, before the entry's ceiling applies. */
	readonly readScope?: (claims: JWTPayload) => readonly string[] | undefined;
}

const defaultReadSubjectHandle = (claims: JWTPayload): string | null =>
	typeof claims.sub === "string" && claims.sub.length > 0 ? claims.sub : null;

/**
 * The ID-JAG default: `sub` is unique only within its issuer (or its
 * issuer and tenant), so the handle carries both. An issuer identifier has
 * no fragment (RFC 8414 §2), so the first `#` always ends it.
 */
const idJagSubjectHandle =
	(issuer: string) =>
	(claims: JWTPayload): string | null => {
		if (typeof claims.sub !== "string" || claims.sub.length === 0) return null;
		const tenant =
			typeof claims.tenant === "string" && claims.tenant.length > 0 ? claims.tenant : null;
		return tenant === null ? `${issuer}#${claims.sub}` : `${issuer}#${tenant}#${claims.sub}`;
	};

/**
 * The `scope` claim, by RFC 6749 §3.3's grammar. The claim is the issuer's,
 * so it is read tolerantly — split on any whitespace, keeping the
 * scope-tokens (`parseScopeTokens`) — and a claim that is present but names
 * none is an empty ceiling, never `undefined`, which would read as "no claim"
 * and hand the entry's whole `allowedScopes` over instead.
 */
const defaultReadScope = (claims: JWTPayload): readonly string[] | undefined =>
	typeof claims.scope === "string" && claims.scope.length > 0
		? parseScopeTokens(claims.scope)
		: undefined;

/** `resource` as an ID-JAG carries it: one string or a list, or nothing. */
const readResources = (claims: JWTPayload): readonly string[] | undefined => {
	const raw = claims.resource;
	if (typeof raw === "string") return raw.length > 0 ? [raw] : undefined;
	if (Array.isArray(raw) && raw.every((r) => typeof r === "string" && r.length > 0)) {
		return raw.length > 0 ? (raw as readonly string[]) : undefined;
	}
	return undefined;
};

/**
 * jose error codes that mean "this assertion does not verify". Anything else
 * (a JWKS endpoint that timed out, answered non-200 or published an unparsable
 * set; a network failure) means no conclusion was reached, and is thrown so the
 * grant answers `503` instead of calling a good credential bad.
 */
const REFUSAL_CODES: ReadonlySet<string> = new Set([
	"ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
	"ERR_JWT_CLAIM_VALIDATION_FAILED",
	"ERR_JWT_EXPIRED",
	"ERR_JWT_INVALID",
	"ERR_JWS_INVALID",
	"ERR_JOSE_ALG_NOT_ALLOWED",
	"ERR_JOSE_NOT_SUPPORTED",
	"ERR_JWKS_NO_MATCHING_KEY",
	"ERR_JWKS_MULTIPLE_MATCHING_KEYS",
]);

const isRefusal = (err: unknown): boolean =>
	err instanceof errors.JOSEError && REFUSAL_CODES.has(err.code);

/**
 * The {@link AssertionVerifier} over a trust registry: several issuers, each
 * with its own keys and terms (clients, subjects, scopes, audiences).
 *
 * The unverified `iss` is looked up first, so an unregistered issuer is refused
 * before any key fetch or signature check (a probe costs no JWKS fetch), and an
 * assertion claiming issuer B is verified against B's keys only. `exp` is
 * mandatory (RFC 7523 §3 item 4), and `exp` / `nbf` / `iat` must be
 * NumericDates: jose only checks for a number, so `exp: 1e400` would never
 * expire. An `iat` further ahead of this server's clock than the entry's
 * clock tolerance is refused. The result carries the entry's scope and
 * audience ceilings, `iat` as `issuedAt` when the assertion carries one, and
 * `exp` as `expiresAt`, which caps the issued token.
 *
 * An entry with `profile: "id-jag"` accepts the Identity Assertion JWT
 * Authorization Grant (draft-ietf-oauth-identity-assertion-authz-grant) and
 * also requires:
 * - header `typ` `oauth-id-jag+jwt` (§3, RFC 8725 §3.11);
 * - `aud` exactly `issuerIdentifier` (never the token endpoint URL), as a
 *   string or a one-element array;
 * - `client_id` naming the client authenticated at the token endpoint;
 * - `jti`, `iat` and `sub`, with each `jti` accepted once per issuer until
 *   `exp` (`replaySeenSet`). A `jti` over `MAX_JTI_LENGTH`, or a lifetime or
 *   `iat` age over `MAX_ASSERTION_LIFETIME_SECONDS` plus clock tolerance, is
 *   refused before it is recorded, so the replay record stays bounded;
 * - `scope` and `resource` as claims, intersected with `allowedScopes` and
 *   `allowedAudiences` (a resource the entry does not admit is refused);
 * - the handle `<iss>#<sub>` (or `<iss>#<tenant>#<sub>`): `sub` is unique only
 *   within its issuer, and linking it to a local principal is the Store's job.
 *
 * Every refusal is the same `null`, so a caller cannot probe which issuers or
 * subjects are registered; the reason goes to `logger` only. Replay within
 * `exp` is detected for ID-JAG only.
 */
export function createRegistryAssertionVerifier(
	options: RegistryAssertionVerifierOptions,
): AssertionVerifier {
	const {
		registry,
		audience,
		issuerIdentifier,
		replaySeenSet,
		kind = "jwt-registry",
		logger,
	} = options;
	// A refusal the grant cannot tell apart from any other, said in the log.
	// Every field is the registry's or a number, never the assertion's text.
	const refused = (
		entry: AssertionIssuerEntry,
		fields: { readonly reason: "lifetime" | "numeric_date" } & Record<string, unknown>,
	): null => {
		logger?.warn({ kind, issuer: entry.issuer, ...fields }, "jwt_bearer_assertion_refused");
		return null;
	};
	const audiences = typeof audience === "string" ? [audience] : [...audience];
	if (audiences.length === 0 || audiences.some((a) => a.length === 0)) {
		throw new Error(
			"createRegistryAssertionVerifier: audience is required — an assertion without " +
				"a pinned audience is replayable from another service (RFC 7523 §3).",
		);
	}
	if (issuerIdentifier !== undefined && issuerIdentifier.length === 0) {
		throw new Error("createRegistryAssertionVerifier: issuerIdentifier must not be empty.");
	}

	// Remote key sets are cached by URI and tuning, not by entry: a registry
	// backed by a store hands back a fresh entry object per lookup, and the
	// cache is what makes a rotation cost one refetch rather than one per
	// request. Two entries naming one URI with different tuning get two key
	// sets — neither inherits the other's.
	const remoteSets = createRemoteKeySetCache({ fetch: options.fetch });
	const keyFor = (entry: AssertionIssuerEntry): unknown => {
		const { keys } = entry;
		switch (keys.type) {
			case "key":
				return keys.key;
			case "jwks":
				return createLocalJWKSet(keys.jwks);
			case "jwks_uri":
				return remoteSets.keySetFor(keys.uri, {
					cacheMaxAgeMs: keys.cacheMaxAgeMs,
					cooldownMs: keys.cooldownMs,
					timeoutMs: keys.timeoutMs,
				});
		}
	};

	return {
		kind,

		async verify(
			assertion: string,
			context: AssertionVerificationContext = {},
		): Promise<AssertionVerificationResult | null> {
			let unverified: JWTPayload;
			try {
				unverified = decodeJwt(assertion);
			} catch {
				return null;
			}
			// The `iss` is the client's input, handed to a registry a deployment
			// may back with its own store: one that cannot name an issuer (core's
			// identifier rule, as for `client_id`) is refused without a lookup,
			// so it cannot make the registry throw — an outage — either.
			if (!isWellFormedIdentifier(unverified.iss)) {
				logger?.warn({ kind, reason: "malformed_issuer" }, "jwt_bearer_assertion_refused");
				return null;
			}

			// A registry outage propagates: it is not a refusal.
			const entry = await registry.findIssuer(unverified.iss);
			if (entry === null) return null;
			if (entry.expiresAt !== undefined && entry.expiresAt.getTime() <= Date.now()) return null;
			if (entry.allowedClients !== undefined) {
				if (context.clientId === undefined || !entry.allowedClients.includes(context.clientId)) {
					return null;
				}
			}

			const idJag = entry.profile === "id-jag";
			if (idJag) {
				// Both are composition, not request, faults: thrown so the grant
				// answers 503 and logs, rather than refusing every device of an
				// issuer whose entry the operator got half right.
				if (issuerIdentifier === undefined) {
					throw new Error(
						`createRegistryAssertionVerifier: entry ${entry.issuer} has profile "id-jag" ` +
							"but no issuerIdentifier was configured — an ID-JAG's aud must be this " +
							"server's issuer identifier (RFC 8414).",
					);
				}
				if (replaySeenSet === undefined) {
					throw new Error(
						`createRegistryAssertionVerifier: entry ${entry.issuer} has profile "id-jag" ` +
							"but no replaySeenSet was configured — an ID-JAG's jti must be accepted once.",
					);
				}
				// An ID-JAG names the client that will present it, so an
				// unauthenticated presenter can never match (§4: client
				// authentication is required).
				if (context.clientId === undefined) return null;
			}

			const clockTolerance = entry.clockToleranceSeconds ?? 60;
			// A store-backed registry's rows are not validated on the way out,
			// and a tolerance of NaN, Infinity or a string switches jose's exp
			// check and the lifetime ceiling off. A composition fault, not a
			// refusal: thrown, so the grant answers 503 and logs it.
			if (!isValidAssertionClockTolerance(clockTolerance)) {
				throw new Error(
					`createRegistryAssertionVerifier: entry ${entry.issuer}: ${describeInvalidAssertionClockTolerance(clockTolerance)}.`,
				);
			}
			let claims: JWTPayload;
			try {
				({ payload: claims } = await jwtVerify(assertion, keyFor(entry) as never, {
					issuer: entry.issuer,
					audience: idJag ? (issuerIdentifier as string) : audiences,
					clockTolerance,
					algorithms: [...entry.algorithms],
					// RFC 7523 §3 item 4: `exp` is mandatory, and jose checks it only
					// when present. `iat` and `nbf` stay optional, except that ID-JAG
					// §3 requires iat, jti, sub and client_id.
					requiredClaims: idJag ? ["exp", "iat", "jti", "sub", "client_id"] : ["exp"],
					// An ID-JAG's `iat` is bounded too: an old assertion with a
					// distant `exp` is a stale grant and a long-lived replay record.
					// The same hour the `private_key_jwt` verifier allows.
					...(idJag ? { maxTokenAge: MAX_ASSERTION_LIFETIME_SECONDS } : {}),
					...(idJag ? { typ: ID_JAG_TYP } : {}),
				}));
			} catch (err) {
				if (isRefusal(err)) return null;
				throw err;
			}
			// Before anything computes a lifetime from them — the replay
			// record's expiry below, the grant's token lifetime after.
			const malformedClaim = malformedNumericDateClaim(claims);
			if (malformedClaim !== undefined) {
				return refused(entry, { reason: "numeric_date", claim: malformedClaim });
			}
			// Read before any claims reader runs, so the issue time reported is
			// the one verified. One beyond this server's clock plus the tolerance
			// is refused, as `verifyJwt` refuses it: reported, it would read as
			// later than any boundary it is compared with.
			const issuedAt = claims.iat;
			if (issuedAt !== undefined && issuedAt > Math.floor(Date.now() / 1000) + clockTolerance) {
				return null;
			}

			if (idJag) {
				// ID-JAG §3: aud is one issuer identifier, as a string or a
				// one-element array. jose accepts any array that contains the
				// value; the profile does not.
				if (Array.isArray(claims.aud) && claims.aud.length !== 1) return null;
				if (claims.client_id !== context.clientId) return null;
				// Non-empty and bounded (`MAX_JTI_LENGTH`): it is a seen-set key
				// kept until `exp`, so the issuer's claim does not decide its size.
				const jti = claims.jti;
				if (!isRecordableJti(jti)) return null;
				// At most an hour past now (`lifetime.mts`), plus the clock
				// tolerance as in every other time check. Refused before the jti
				// is recorded: the record lives until `exp`.
				const { exceeded, lifetimeSeconds, maxLifetimeSeconds } = assertionLifetime(
					claims.exp as number,
					Math.floor(Date.now() / 1000),
					clockTolerance,
				);
				if (exceeded) {
					return refused(entry, { reason: "lifetime", lifetimeSeconds, maxLifetimeSeconds });
				}
				// Accepted once for its lifetime. `exp` verified above; the floor
				// keeps a within-tolerance assertion from reading as expired at
				// issue in the store.
				const expiresAtMs = Math.max((claims.exp as number) * 1000, Date.now() + 1_000);
				const fresh = await replaySeenSet?.markSeen(
					`jwt-bearer:id-jag:${entry.issuer}`,
					jti,
					expiresAtMs,
				);
				if (fresh !== true) return null;
			}

			if (
				entry.allowedSubjects !== undefined &&
				(typeof claims.sub !== "string" || !entry.allowedSubjects.includes(claims.sub))
			) {
				return null;
			}
			const readers = options.readersFor?.(entry);
			const readHandle =
				readers?.readSubjectHandle ??
				(idJag ? idJagSubjectHandle(entry.issuer) : defaultReadSubjectHandle);
			const subjectHandle = readHandle(claims);
			if (subjectHandle === null || subjectHandle.length === 0) return null;

			const claimed = (readers?.readScope ?? defaultReadScope)(claims);
			const scope =
				entry.allowedScopes === undefined
					? claimed
					: claimed === undefined
						? entry.allowedScopes
						: claimed.filter((s) => entry.allowedScopes?.includes(s));

			// The audience ceiling: an ID-JAG's `resource` claim, bounded by the
			// entry's list (a resource the entry does not admit is refused);
			// otherwise the entry's list alone, or nothing.
			let audienceCeiling = entry.allowedAudiences;
			if (idJag) {
				const resources = readResources(claims);
				if (resources !== undefined) {
					const admitted =
						entry.allowedAudiences === undefined
							? resources
							: resources.filter((r) => entry.allowedAudiences?.includes(r));
					if (admitted.length === 0) return null;
					audienceCeiling = admitted;
				}
			}

			return {
				subjectHandle,
				issuer: entry.issuer,
				...(scope === undefined ? {} : { scope }),
				...(audienceCeiling === undefined ? {} : { audience: audienceCeiling }),
				...(issuedAt === undefined ? {} : { issuedAt }),
				// NumericDate-checked above. Kept as claimed: one already past
				// within the clock tolerance is refused by the grant, not here.
				expiresAt: claims.exp as number,
			};
		},
	};
}
