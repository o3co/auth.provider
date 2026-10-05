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

import type { JWTPayload } from "jose";
import type { KeyLike } from "../keys/KeyStore.mjs";
import { createMemoryAssertionIssuerRegistry } from "./issuerRegistry.mjs";
import { createRegistryAssertionVerifier } from "./registryAssertionVerifier.mjs";
import type { AssertionVerifier } from "./types.mjs";

/**
 * How the handle is derived from a verified assertion's claims.
 *
 * Defaults to `sub`, which is what RFC 7523 §3 puts the principal in. A
 * deployment whose device tokens carry the identifier elsewhere supplies its
 * own reader rather than reshaping its tokens.
 */
export type SubjectHandleReader = (claims: JWTPayload) => string | null;

export interface JwtAssertionVerifierOptions {
	/**
	 * Public key(s) of the authority that signs assertions.
	 *
	 * Not this provider's signing key, and the distinction is load-bearing: an
	 * assertion is issued by whatever enrolled the device, and accepting one
	 * signed by our own issuer key would let anything holding a token we minted
	 * present it as a device credential.
	 */
	readonly key: KeyLike;
	/** Required `iss`. RFC 7523 §3 makes it mandatory, and so does this. */
	readonly issuer: string;
	/**
	 * Required `aud` — this authorization server.
	 *
	 * RFC 7523 §3 requires the AS to reject an assertion not addressed to it,
	 * and the reason is concrete: without it, an assertion minted for a
	 * *different* service can be replayed here.
	 */
	readonly audience: string;
	/**
	 * Signature algorithms accepted, e.g. `["EdDSA"]`.
	 *
	 * Required, with no default. jose otherwise accepts anything the supplied
	 * key can verify, which is a wider contract than a deployment means when it
	 * configures one key — and "accepts whatever fits" is how an assertion
	 * signed with an unintended algorithm gets through.
	 */
	readonly algorithms: readonly string[];
	/**
	 * Clock skew for `exp` / `nbf`, in seconds. Default 60. An assertion past
	 * its `exp` inside the tolerance verifies, but the jwt-bearer grant
	 * refuses it: no lifetime is left for a token to inherit.
	 */
	readonly clockToleranceSeconds?: number;
	/**
	 * How long an assertion may live, `exp − iat`, in seconds: the issuer
	 * entry's `maxLifetimeSeconds`. Default an hour, at most a day.
	 */
	readonly maxLifetimeSeconds?: number;
	/** Defaults to reading `sub`. */
	readonly readSubjectHandle?: SubjectHandleReader;
	/** Reads `scope` (space-delimited, per RFC 8693 §2.1) by default. */
	readonly readScope?: (claims: JWTPayload) => readonly string[] | undefined;
}

/**
 * The vendor-neutral {@link AssertionVerifier}: an RFC 7523 §3 JWT signed by an
 * authority this deployment trusts, checked against one static key. It is a
 * one-entry {@link createRegistryAssertionVerifier}; several issuers, JWKS keys
 * or per-issuer terms need a registry and that verifier directly. Platform
 * attestations (DeviceCheck, Play Integrity) are the operator's own port.
 *
 * Returns `null` for a bad signature, a wrong `iss` or `aud` (without `aud`, an
 * assertion minted for another service is replayable here), an expired
 * assertion, one with no `exp` (RFC 7523 §3 item 4; jose checks `exp` only when
 * present), and claims with no usable handle. `algorithms` has no default, so
 * `alg: none` and every unlisted algorithm are refused.
 *
 * `exp` is the only lifetime bound: it is reported as `expiresAt` and the
 * jwt-bearer grant caps its token there. `iat`, when present, is reported as
 * `issuedAt`. Replay within `exp` is not detected
 * (no `jti` tracking, RFC 7523 §3 item 7), so authorities should mint
 * short-lived assertions. Verification here is local and never fails to be
 * attempted; a vendor-backed verifier throws instead and the grant answers 503.
 */
export function createJwtAssertionVerifier(
	options: JwtAssertionVerifierOptions,
): AssertionVerifier {
	const {
		key,
		issuer,
		audience,
		algorithms,
		clockToleranceSeconds,
		maxLifetimeSeconds,
		readSubjectHandle,
		readScope,
	} = options;

	if (issuer.length === 0 || audience.length === 0) {
		throw new Error(
			"createJwtAssertionVerifier: issuer and audience are required — an assertion " +
				"without a pinned issuer is signed by anyone the key belongs to, and one " +
				"without a pinned audience is replayable from another service (RFC 7523 §3).",
		);
	}
	if (algorithms.length === 0) {
		throw new Error(
			"createJwtAssertionVerifier: algorithms must name at least one algorithm — " +
				"omitting it lets jose accept anything the key can verify, which is wider " +
				"than configuring one key means.",
		);
	}

	const readers = {
		...(readSubjectHandle === undefined ? {} : { readSubjectHandle }),
		...(readScope === undefined ? {} : { readScope }),
	};
	return createRegistryAssertionVerifier({
		kind: "jwt",
		audience,
		registry: createMemoryAssertionIssuerRegistry([
			{
				issuer,
				keys: { type: "key", key },
				algorithms,
				...(clockToleranceSeconds === undefined ? {} : { clockToleranceSeconds }),
				...(maxLifetimeSeconds === undefined ? {} : { maxLifetimeSeconds }),
			},
		]),
		readersFor: () => readers,
	});
}
