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

import { type JWTPayload, jwtVerify } from "jose";
import type { KeyLike } from "../keys/KeyStore.mjs";
import type { AssertionVerificationResult, AssertionVerifier } from "./types.mjs";

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
	/** Clock skew for `exp` / `nbf`, in seconds. Default 60. */
	readonly clockToleranceSeconds?: number;
	/** Defaults to reading `sub`. */
	readonly readSubjectHandle?: SubjectHandleReader;
	/** Reads `scope` (space-delimited, per RFC 8693 §2.1) by default. */
	readonly readScope?: (claims: JWTPayload) => readonly string[] | undefined;
}

const defaultReadSubjectHandle: SubjectHandleReader = (claims) =>
	typeof claims.sub === "string" && claims.sub.length > 0 ? claims.sub : null;

const defaultReadScope = (claims: JWTPayload): readonly string[] | undefined =>
	typeof claims.scope === "string" && claims.scope.length > 0
		? claims.scope.split(" ").filter((s) => s.length > 0)
		: undefined;

/**
 * The vendor-neutral {@link AssertionVerifier}: a JWT signed by an authority
 * this deployment trusts (#301).
 *
 * This is the RFC 7523 §3 shape — `iss`, `sub`, `aud`, `exp` checked against a
 * configured key — and it ships because otherwise every deployment hand-rolls
 * JWT verification for its device tokens, which is exactly where "a bare
 * identifier was accepted as a login" comes from. Platform attestations (Apple
 * DeviceCheck, Play Integrity) need a vendor call and are the operator's own
 * implementation of the port.
 *
 * ## What it refuses, and why each one is here
 *
 * - **A bad signature, a wrong `iss`, a wrong `aud`, an expired assertion** —
 *   `null`, i.e. not verified. `aud` in particular: an assertion addressed to
 *   another service is replayable here without it.
 * - **An assertion with no `exp`** — `null`. RFC 7523 §3 item 4 makes it
 *   mandatory, and jose does not: it validates `exp` only when present, so an
 *   assertion that omits it would otherwise be accepted for ever. There is
 *   no lifetime ceiling beyond `exp` itself (no `maxTokenAge`): the RFC gives
 *   the issuing authority that decision, and this verifier has no knob for
 *   second-guessing it.
 * - **Replay within `exp` is not detected here.** RFC 7523 §3 item 7 lets
 *   an AS track `jti` to refuse a second presentation; this verifier does
 *   not, and neither does the grant that consumes it. An assertion is
 *   accepted as many times as it is presented until it expires, so an
 *   authority should mint short-lived assertions.
 * - **A claims set with no usable handle** — `null`. A verified signature over
 *   a token naming nobody is not an authentication.
 * - **`alg: none` and every unlisted algorithm** — `algorithms` is required
 *   with no default, so a deployment names what it accepts rather than
 *   inheriting "anything this key can verify".
 *
 * A verification that could not be *attempted* is not modelled here: this
 * implementation is local and cannot fail that way. A vendor-backed verifier
 * throws instead, and the grant answers `503`.
 */
export function createJwtAssertionVerifier(
	options: JwtAssertionVerifierOptions,
): AssertionVerifier {
	const {
		key,
		issuer,
		audience,
		algorithms,
		clockToleranceSeconds = 60,
		readSubjectHandle = defaultReadSubjectHandle,
		readScope = defaultReadScope,
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

	return {
		kind: "jwt",

		async verify(assertion: string): Promise<AssertionVerificationResult | null> {
			let claims: JWTPayload;
			try {
				({ payload: claims } = await jwtVerify(assertion, key as never, {
					issuer,
					audience,
					clockTolerance: clockToleranceSeconds,
					algorithms: [...algorithms],
					// RFC 7523 §3 item 4: `exp` is mandatory. jose validates it only
					// when present, so without naming it here an assertion that
					// simply omits `exp` never expires — a credential whose theft
					// is permanent. `iat` and `nbf` stay optional (items 5 and 6
					// are MAYs), and both are validated when present.
					requiredClaims: ["exp"],
				}));
			} catch {
				// Not verified. Deliberately not rethrown: a caller must not be
				// able to tell a bad signature from a wrong audience from an
				// expired token, and the grant answers all of them the same way.
				return null;
			}

			const subjectHandle = readSubjectHandle(claims);
			if (subjectHandle === null || subjectHandle.length === 0) return null;

			const scope = readScope(claims);
			return scope === undefined ? { subjectHandle } : { subjectHandle, scope };
		},
	};
}
