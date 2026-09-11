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
import type { AssertionIssuerEntry, AssertionIssuerRegistry } from "./issuerRegistry.mjs";
import type {
	AssertionVerificationContext,
	AssertionVerificationResult,
	AssertionVerifier,
} from "./types.mjs";

export interface RegistryAssertionVerifierOptions {
	readonly registry: AssertionIssuerRegistry;
	/**
	 * What an assertion's `aud` must name — this authorization server. RFC 7523
	 * §3 requires the AS to reject an assertion not addressed to it, and the
	 * reason is concrete: without it, an assertion minted for a *different*
	 * service is replayable here. Several values are accepted so a deployment
	 * can name both its issuer identifier and its token endpoint URL.
	 */
	readonly audience: string | readonly string[];
	/** Adapter kind, for logs and boot diagnostics. Default `"jwt-registry"`. */
	readonly kind?: string;
}

const defaultReadSubjectHandle = (claims: JWTPayload): string | null =>
	typeof claims.sub === "string" && claims.sub.length > 0 ? claims.sub : null;

const defaultReadScope = (claims: JWTPayload): readonly string[] | undefined =>
	typeof claims.scope === "string" && claims.scope.length > 0
		? claims.scope.split(" ").filter((s) => s.length > 0)
		: undefined;

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
 * Every refusal is the same `null`. Distinguishing them would let a caller
 * probe for which issuers are registered or which subjects are admitted.
 * Replay within `exp` is not detected here; an issuer should mint short-lived
 * assertions (the ID-JAG profile's mandatory `jti` is #526).
 */
export function createRegistryAssertionVerifier(
	options: RegistryAssertionVerifierOptions,
): AssertionVerifier {
	const { registry, audience, kind = "jwt-registry" } = options;
	const audiences = typeof audience === "string" ? [audience] : [...audience];
	if (audiences.length === 0 || audiences.some((a) => a.length === 0)) {
		throw new Error(
			"createRegistryAssertionVerifier: audience is required — an assertion without " +
				"a pinned audience is replayable from another service (RFC 7523 §3).",
		);
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

			let claims: JWTPayload;
			try {
				({ payload: claims } = await jwtVerify(assertion, keyFor(entry) as never, {
					issuer: entry.issuer,
					audience: audiences,
					clockTolerance: entry.clockToleranceSeconds ?? 60,
					algorithms: [...entry.algorithms],
					// RFC 7523 §3 item 4: `exp` is mandatory. jose validates it only
					// when present, so without naming it an assertion that omits it
					// never expires. `iat` and `nbf` stay optional (MAYs) and are
					// validated when present.
					requiredClaims: ["exp"],
				}));
			} catch (err) {
				if (isRefusal(err)) return null;
				throw err;
			}

			if (
				entry.allowedSubjects !== undefined &&
				(typeof claims.sub !== "string" || !entry.allowedSubjects.includes(claims.sub))
			) {
				return null;
			}
			const subjectHandle = (entry.readSubjectHandle ?? defaultReadSubjectHandle)(claims);
			if (subjectHandle === null || subjectHandle.length === 0) return null;

			const claimed = (entry.readScope ?? defaultReadScope)(claims);
			const scope =
				entry.allowedScopes === undefined
					? claimed
					: claimed === undefined
						? entry.allowedScopes
						: claimed.filter((s) => entry.allowedScopes?.includes(s));

			return {
				subjectHandle,
				issuer: entry.issuer,
				...(scope === undefined ? {} : { scope }),
				...(entry.allowedAudiences === undefined ? {} : { audience: entry.allowedAudiences }),
			};
		},
	};
}
