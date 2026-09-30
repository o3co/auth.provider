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
	isRecordableJti,
	MAX_JTI_LENGTH,
	malformedNumericDateClaim,
} from "@o3co/auth-provider-core";
import { decodeJwt, decodeProtectedHeader, type JWK } from "jose";
import { DPoPError } from "./errors.mjs";
import { computeJkt } from "./thumbprint.mjs";

export interface DPoPProofClaims {
	readonly htm: string;
	readonly htu: string;
	readonly iat: number;
	readonly jti: string;
	/**
	 * `base64url(SHA-256(access token))` — RFC 9449 §4.2. Optional here: absent
	 * at the token endpoint, REQUIRED at a protected resource, which verifies it
	 * against the token it was handed (§7.1). That binding stops a proof captured
	 * with one request from being replayed with a different stolen token.
	 */
	readonly ath?: string;
	/** The server-provided nonce echoed back (RFC 9449 §8 / §9). */
	readonly nonce?: string;
}

/**
 * Result of structural DPoP proof parsing: flat fields, with the proof-key
 * JWK and its RFC 7638 SHA-256 thumbprint (`jkt`) computed at parse time so
 * consumers (the verifier, the grant-side `cnf` claim) need not re-derive it.
 * The signature is not verified here; that is the verifier's job.
 */
export interface DPoPProof {
	/** Proof-of-possession public key from the JOSE protected header. */
	readonly jwk: JWK;
	/** JOSE `alg` header value (whitelist enforcement is in the verifier). */
	readonly alg: string;
	/** RFC 7638 SHA-256 thumbprint of `jwk` — the value used in `cnf.jkt`. */
	readonly jkt: string;
	readonly claims: DPoPProofClaims;
	/** Original raw JWT — needed for the verifier's signature check. */
	readonly raw: string;
}

/**
 * Parse a raw DPoP header value into a structured `DPoPProof`. Throws
 * `DPoPError` for malformed input; does NOT verify the signature or the
 * semantic claims (htm, htu, iat), which the verifier does.
 *
 * Checks, in order:
 *   1. JWT shape (3 parts)
 *   2. typ = dpop+jwt
 *   3. alg present (the allowlist is the verifier's)
 *   4. jwk present in the header, public-only (private members screened by name)
 *   5. required claims present with correct types; a `jti` of at most
 *      `MAX_JTI_LENGTH` characters; `iat`, and any `exp` / `nbf`, a NumericDate
 *   6. jkt computed via RFC 7638 SHA-256 thumbprint
 *
 * The thumbprint runs last because it is the parser's only cryptographic
 * operation, so a proof with missing claims is refused without paying for it.
 */
export const parseProof = async (raw: string): Promise<DPoPProof> => {
	// JWT shape: exactly 3 dot-separated parts
	if (typeof raw !== "string" || raw.split(".").length !== 3) {
		throw new DPoPError("malformed_proof", "DPoP header is not a JWT");
	}

	let header: { typ?: unknown; alg?: unknown; jwk?: unknown };
	try {
		header = decodeProtectedHeader(raw);
	} catch {
		throw new DPoPError("malformed_proof", "DPoP header is not parseable");
	}

	if (header.typ !== "dpop+jwt") {
		// Fixed text: the value is the client's, and the refusal's message
		// reaches the dispatcher's log line through its projection.
		throw new DPoPError("typ_mismatch", "typ is not dpop+jwt");
	}

	// alg must be a non-empty string; the allowlist is enforced in the verifier.
	if (typeof header.alg !== "string" || header.alg.length === 0) {
		throw new DPoPError("malformed_proof", "missing or non-string alg");
	}

	if (!header.jwk || typeof header.jwk !== "object") {
		throw new DPoPError("missing_jwk", "JOSE header has no jwk");
	}

	// The JWK must carry public key material only.
	const jwk = header.jwk as Record<string, unknown>;
	const privateKeyFields = ["d", "p", "q", "dp", "dq", "qi", "k"];
	for (const field of privateKeyFields) {
		if (field in jwk) {
			throw new DPoPError("private_jwk", `JWK carries private material: ${field}`);
		}
	}

	let claims: Record<string, unknown>;
	try {
		claims = decodeJwt(raw) as Record<string, unknown>;
	} catch {
		throw new DPoPError("malformed_proof", "DPoP body is not parseable");
	}

	for (const claim of ["htm", "htu", "iat", "jti"] as const) {
		if (!(claim in claims)) {
			throw new DPoPError("missing_claim", `missing required claim: ${claim}`);
		}
	}

	// Wrong-type claims are `malformed_proof`, distinct from `missing_claim`:
	// audit triage must tell "client omitted htm" from "client sent iat as a
	// string".
	if (
		typeof claims.htm !== "string" ||
		typeof claims.htu !== "string" ||
		typeof claims.iat !== "number" ||
		typeof claims.jti !== "string"
	) {
		throw new DPoPError("malformed_proof", "invalid claim types");
	}

	// The jti is the key the verifier records in the seen-set for
	// `dpop.replayStoreTtlSeconds`, and this runs before the signature is checked
	// and, at the token endpoint, before the client is authenticated: whoever
	// sends the proof chooses it. RFC 9449 §4.2 asks only for uniqueness, which a
	// UUID (36 characters) already gives, so an over-long one is malformed here
	// and never reaches the store.
	if (!isRecordableJti(claims.jti)) {
		throw new DPoPError(
			"malformed_proof",
			`jti must be a non-empty string of at most ${MAX_JTI_LENGTH} characters`,
		);
	}

	// `iat` — and an `exp` or `nbf` the proof carries — must be a NumericDate
	// (core's `isNumericDate`), not merely a number: JSON's `1e400` parses to
	// Infinity, which the iat window would report as a drift of Infinity and
	// which jose accepts as an `exp` that never passes. Either is a malformed
	// proof, not a clock difference.
	if (malformedNumericDateClaim(claims) !== undefined) {
		throw new DPoPError("malformed_proof", "invalid claim types");
	}

	// `ath` is optional at this layer but must not be silently dropped when
	// present-and-wrong-typed: dropping it would downgrade a proof the client
	// meant to bind to a specific access token into an unbound one, which is
	// precisely the property a protected resource relies on.
	if ("ath" in claims && typeof claims.ath !== "string") {
		throw new DPoPError("malformed_proof", "invalid claim types");
	}
	// Same rule for `nonce`: present-and-wrong-typed is malformed, not absent,
	// so it cannot read as "no nonce was sent".
	if ("nonce" in claims && typeof claims.nonce !== "string") {
		throw new DPoPError("malformed_proof", "invalid claim types");
	}

	// RFC 7638 thumbprint over the validated JWK. jose throws `JWKInvalid` for a
	// malformed shape (EC key missing `crv`/`x`/`y`, RSA missing `n`/`e`); the
	// private-member screen above checks names only. Wrap any jose error so the
	// `DPoPError` contract holds at the boundary.
	let jkt: string;
	try {
		jkt = await computeJkt(jwk as JWK);
	} catch (err) {
		// Fixed text: jose's error is the cause, not part of the message.
		throw new DPoPError("malformed_proof", "invalid JWK", undefined, undefined, { cause: err });
	}

	return {
		jwk: jwk as JWK,
		alg: header.alg,
		jkt,
		claims: {
			htm: claims.htm,
			htu: claims.htu,
			iat: claims.iat,
			jti: claims.jti,
			...(typeof claims.ath === "string" ? { ath: claims.ath } : {}),
			...(typeof claims.nonce === "string" ? { nonce: claims.nonce } : {}),
		},
		raw,
	};
};
