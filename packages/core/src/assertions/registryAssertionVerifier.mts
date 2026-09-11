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
	createLocalJWKSet,
	createRemoteJWKSet,
	decodeJwt,
	errors,
	type JWTPayload,
	jwtVerify,
} from "jose";
import type { ReplaySeenSet } from "../replay-seen-set/types.mjs";
import type { AssertionIssuerEntry, AssertionIssuerRegistry } from "./issuerRegistry.mjs";
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
	 * only `aud` an ID-JAG may name (#526). Required by any entry whose
	 * `profile` is `"id-jag"`; the token endpoint URL is not an alias there.
	 */
	readonly issuerIdentifier?: string;
	/**
	 * Where ID-JAG `jti` values are recorded so each assertion is accepted once
	 * (#526). Keyed per issuer, expiring with the assertion. Required by any
	 * `"id-jag"` entry; an outage of the store throws, so the grant answers
	 * `503` rather than accepting a replay.
	 */
	readonly replaySeenSet?: ReplaySeenSet;
	/** Adapter kind, for logs and boot diagnostics. Default `"jwt-registry"`. */
	readonly kind?: string;
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

const defaultReadScope = (claims: JWTPayload): readonly string[] | undefined =>
	typeof claims.scope === "string" && claims.scope.length > 0
		? claims.scope.split(" ").filter((s) => s.length > 0)
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
 * jose error codes that mean "this assertion does not verify". Everything else
 * — a JWKS endpoint that timed out, answered non-200, or published a set that
 * does not parse; a network failure — means the verifier could not reach a
 * conclusion, and is thrown so the grant answers `503` rather than telling a
 * device its credential is bad when the truth is that the issuer's endpoint
 * is down (the #408 distinction).
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
 * The {@link AssertionVerifier} over a trust registry (#525): "we trust these
 * N issuers, each with their own keys and terms", where
 * `createJwtAssertionVerifier` was "this one key, this one issuer".
 *
 * ## Order of checks, and why
 *
 * 1. Decode the claims without verifying, read `iss`, and look it up. An
 *    issuer nobody registered is refused **before any signature work**: no
 *    key is fetched, no signature is checked. This is what keeps an
 *    unregistered issuer from costing a JWKS fetch per probe, and what makes
 *    "signed by A, claiming to be B" fail on B's keys rather than A's.
 * 2. The entry must not have expired, and the presenting client must be one
 *    the entry admits (`allowedClients`; an unauthenticated presenter passes
 *    only when the entry names no list).
 * 3. Signature, `iss`, `aud`, `exp` (mandatory, RFC 7523 §3 item 4), `nbf` /
 *    `iat` when present, against the entry's keys and algorithms.
 * 4. `sub` must be one the entry admits (`allowedSubjects`), and the handle
 *    reader must find a handle.
 * 5. The result carries the entry's ceilings: the scope claim intersected
 *    with `allowedScopes`, and `allowedAudiences` as the audience ceiling.
 *
 * ## The ID-JAG profile (#526)
 *
 * An entry with `profile: "id-jag"` accepts the Identity Assertion JWT
 * Authorization Grant (draft-ietf-oauth-identity-assertion-authz-grant) —
 * what an enterprise IdP mints for a client so a resource's authorization
 * server can issue it a token. On top of the checks above, in step 3 and
 * after it:
 *
 * - the JWT header `typ` MUST be `oauth-id-jag+jwt` (§3, RFC 8725 §3.11);
 * - `aud` MUST be this server's issuer identifier — `issuerIdentifier`,
 *   never the token endpoint URL — as one string or a one-element array;
 * - `client_id` MUST name the client that authenticated at the token
 *   endpoint; an unauthenticated presenter is refused — client
 *   authentication is required for this grant;
 * - `jti`, `iat` and `sub` are required, and each `jti` is accepted **once**
 *   for the assertion's lifetime, recorded in `replaySeenSet` per issuer;
 * - `scope` and `resource` travel as claims, not request parameters: the
 *   scope ceiling is the claim intersected with `allowedScopes`, and the
 *   audience ceiling is the `resource` claim intersected with
 *   `allowedAudiences` (a resource the entry does not admit is refused). The
 *   grant then bounds both by the client's registration.
 * - the handle is `<iss>#<sub>` (or `<iss>#<tenant>#<sub>`): `sub` is unique
 *   only within its issuer, and resolving it to a local principal stays
 *   with the Store — an unlinked one is refused there.
 *
 * Every refusal is the same `null`. Distinguishing them would let a caller
 * probe for which issuers are registered or which subjects are admitted.
 * Replay within `exp` is detected for ID-JAG only; a plain RFC 7523 issuer
 * should mint short-lived assertions.
 */
export function createRegistryAssertionVerifier(
	options: RegistryAssertionVerifierOptions,
): AssertionVerifier {
	const { registry, audience, issuerIdentifier, replaySeenSet, kind = "jwt-registry" } = options;
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

	// Remote key sets are cached by URI, not by entry: a registry backed by a
	// store hands back a fresh entry object per lookup, and the cache is what
	// makes a rotation cost one refetch rather than one per request.
	const remoteSets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
	const keyFor = (entry: AssertionIssuerEntry): unknown => {
		const { keys } = entry;
		switch (keys.type) {
			case "key":
				return keys.key;
			case "jwks":
				return createLocalJWKSet(keys.jwks);
			case "jwks_uri": {
				const cached = remoteSets.get(keys.uri);
				if (cached) return cached;
				const set = createRemoteJWKSet(new URL(keys.uri), {
					cacheMaxAge: keys.cacheMaxAgeMs ?? 10 * 60 * 1000,
					cooldownDuration: keys.cooldownMs ?? 30 * 1000,
					timeoutDuration: keys.timeoutMs ?? 5 * 1000,
				});
				remoteSets.set(keys.uri, set);
				return set;
			}
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
			if (typeof unverified.iss !== "string" || unverified.iss.length === 0) return null;

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

			let claims: JWTPayload;
			try {
				({ payload: claims } = await jwtVerify(assertion, keyFor(entry) as never, {
					issuer: entry.issuer,
					audience: idJag ? (issuerIdentifier as string) : audiences,
					clockTolerance: entry.clockToleranceSeconds ?? 60,
					algorithms: [...entry.algorithms],
					// RFC 7523 §3 item 4: `exp` is mandatory. jose validates it only
					// when present, so without naming it an assertion that omits it
					// never expires. `iat` and `nbf` stay optional (MAYs) and are
					// validated when present — except under ID-JAG, where iat,
					// jti, sub and client_id are all required claims (§3).
					requiredClaims: idJag ? ["exp", "iat", "jti", "sub", "client_id"] : ["exp"],
					...(idJag ? { typ: ID_JAG_TYP } : {}),
				}));
			} catch (err) {
				if (isRefusal(err)) return null;
				throw err;
			}

			if (idJag) {
				// ID-JAG §3: aud is one issuer identifier, as a string or a
				// one-element array. jose accepts any array that contains the
				// value; the profile does not.
				if (Array.isArray(claims.aud) && claims.aud.length !== 1) return null;
				if (claims.client_id !== context.clientId) return null;
				const jti = claims.jti;
				if (typeof jti !== "string" || jti.length === 0) return null;
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
			const readHandle =
				entry.readSubjectHandle ??
				(idJag ? idJagSubjectHandle(entry.issuer) : defaultReadSubjectHandle);
			const subjectHandle = readHandle(claims);
			if (subjectHandle === null || subjectHandle.length === 0) return null;

			const claimed = (entry.readScope ?? defaultReadScope)(claims);
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
			};
		},
	};
}
