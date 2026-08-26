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
import { decodeJwt, decodeProtectedHeader, type JWK } from "jose";
import { DPoPError } from "./errors.mjs";
import { computeJkt } from "./thumbprint.mjs";

export interface DPoPProofClaims {
	readonly htm: string;
	readonly htu: string;
	readonly iat: number;
	readonly jti: string;
	/**
	 * `base64url(SHA-256(access token))` — RFC 9449 §4.2.
	 *
	 * Optional here because the claim's necessity depends on where the proof is
	 * presented, which this parser does not know. At the token endpoint there
	 * is no access token yet and the claim is absent; at a protected resource
	 * it is REQUIRED and the resource verifies it against the token it was
	 * handed (§7.1). That binding is what stops a proof captured alongside one
	 * request from being replayed with a different stolen token.
	 */
	readonly ath?: string;
}

/**
 * Result of structural DPoP proof parsing. Layout matches Wave 2 Phase 2
 * spec §5.3 — flat fields, with the proof-key JWK and its RFC 7638 SHA-256
 * thumbprint (`jkt`) computed at parse time so downstream consumers (the
 * verifier in 2b, the grant-side cnf claim in 2c) can route on the binding
 * identity without re-deriving the thumbprint.
 *
 * Signature verification is the verifier's responsibility (Sub-PR 2b) —
 * `parseProof` only validates JOSE shape and claim presence.
 */
export interface DPoPProof {
	/** Proof-of-possession public key from the JOSE protected header. */
	readonly jwk: JWK;
	/** JOSE `alg` header value (whitelist enforcement is in the verifier). */
	readonly alg: string;
	/** RFC 7638 SHA-256 thumbprint of `jwk` — the value used in `cnf.jkt`. */
	readonly jkt: string;
	readonly claims: DPoPProofClaims;
	/** Original raw JWT — needed for signature verification in 2b. */
	readonly raw: string;
}

/**
 * Parse a raw DPoP header value into a structured `DPoPProof`. Throws
 * `DPoPError` for malformed input — does NOT verify the signature or
 * validate semantic claims (htm, htu, iat). Those happen in the
 * verifier (T2.5 / Sub-PR 2b).
 *
 * Validation order follows spec §6 with one performance-driven deviation:
 *   Step 3: JWT shape (3 parts)
 *   Step 4: typ = dpop+jwt
 *   Step 5: alg present (whitelist check is in verifier)
 *   Step 6: jwk present in header
 *   Step 7: jwk is public-only (no private material — name-screened)
 *   Step 9: required claims present + correct types       ← runs BEFORE step 8
 *   Step 8: jkt computed via RFC 7638 SHA-256 thumbprint  ← runs LAST
 *
 * Step 8 is moved AFTER step 9 because `computeJkt` is the only cryptographic
 * operation in the parser (canonical JSON serialization + SHA-256). Cheap
 * structural / type checks run first so a proof with missing claims rejects
 * without burning the thumbprint cost. The spec authorizes this ordering —
 * §6's step numbering is the validation taxonomy, not a literal execution
 * sequence, since steps 7 and 9 don't depend on the jkt value.
 *
 * Per Wave 2 Phase 2 spec §6 + design principle §3.2 (total-order validation).
 */
export const parseProof = async (raw: string): Promise<DPoPProof> => {
	// Step 3 (spec §6): JWT shape — must be exactly 3 dot-separated parts
	if (typeof raw !== "string" || raw.split(".").length !== 3) {
		throw new DPoPError("malformed_proof", "DPoP header is not a JWT");
	}

	let header: { typ?: unknown; alg?: unknown; jwk?: unknown };
	try {
		header = decodeProtectedHeader(raw);
	} catch {
		throw new DPoPError("malformed_proof", "DPoP header is not parseable");
	}

	// Step 4 (spec §6): typ must be exactly "dpop+jwt"
	if (header.typ !== "dpop+jwt") {
		throw new DPoPError("typ_mismatch", `expected typ=dpop+jwt, got ${String(header.typ)}`);
	}

	// Step 5 (spec §6): alg must be present as a non-empty string
	// (whitelist enforcement is in the verifier).
	if (typeof header.alg !== "string" || header.alg.length === 0) {
		throw new DPoPError("malformed_proof", "missing or non-string alg");
	}

	// Step 6 (spec §6): jwk must be present in the protected header
	if (!header.jwk || typeof header.jwk !== "object") {
		throw new DPoPError("missing_jwk", "JOSE header has no jwk");
	}

	// Step 7 (spec §6): JWK must carry public key material only
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

	// Step 9 (spec §6): required claims must be present
	for (const claim of ["htm", "htu", "iat", "jti"] as const) {
		if (!(claim in claims)) {
			throw new DPoPError("missing_claim", `missing required claim: ${claim}`);
		}
	}

	// Step 9 continued: claim type validation.
	// Wrong-type claims are a STRUCTURAL error (`malformed_proof`), distinct
	// from the `missing_claim` branch above — operator audit triage needs to
	// distinguish "client omitted htm" from "client sent iat as a string".
	if (
		typeof claims.htm !== "string" ||
		typeof claims.htu !== "string" ||
		typeof claims.iat !== "number" ||
		typeof claims.jti !== "string"
	) {
		throw new DPoPError("malformed_proof", "invalid claim types");
	}

	// `ath` is optional at this layer but must not be silently dropped when
	// present-and-wrong-typed: dropping it would downgrade a proof the client
	// meant to bind to a specific access token into an unbound one, which is
	// precisely the property a protected resource relies on.
	if ("ath" in claims && typeof claims.ath !== "string") {
		throw new DPoPError("malformed_proof", "invalid claim types");
	}

	// Step 8 (spec §6): RFC 7638 SHA-256 thumbprint over the validated JWK.
	// `computeJkt` delegates to jose's `calculateJwkThumbprint`, which throws
	// `JWKInvalid` for malformed JWK shapes (e.g. EC key missing `crv`/`x`/`y`,
	// RSA missing `n`/`e`). Step 7 only screens for private-material *field
	// names* — shape validity is jose's job. Wrap any jose error so the
	// package's documented `DPoPError` contract holds at the boundary.
	let jkt: string;
	try {
		jkt = await computeJkt(jwk as JWK);
	} catch (err) {
		throw new DPoPError("malformed_proof", `invalid JWK: ${(err as Error).message}`);
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
		},
		raw,
	};
};
