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
	decodeProtectedHeader,
	type JWTPayload as JoseJWTPayload,
	errors as joseErrors,
	jwtVerify,
	type ProtectedHeaderParameters,
} from "jose";
import type { KeyStore } from "../keys/KeyStore.mjs";
import type { Logger } from "../logging/Logger.mjs";

/**
 * Token type — drives default `typ` expectation and selects appropriate
 * post-signature claim checks (e.g. `azp` on refresh tokens).
 */
export type JwtType = "access_token" | "refresh_token" | "id_token";

/**
 * Discriminator for {@link JwtVerificationError}. One reason per failure mode
 * keeps caller `catch` blocks structurally exhaustive when the exhaustive
 * switch over this union is type-checked.
 */
export type JwtVerificationReason =
	| "alg"
	| "iss"
	| "aud"
	| "typ"
	| "azp"
	| "nonce"
	| "signature"
	| "expired"
	| "not_yet_valid"
	| "kid_unknown"
	// `kid_expired` is distinct from `kid_unknown`: an expired kid is an
	// operator-rotation signal (the previous key's expiresAt has passed), an
	// unknown kid is an attacker-fabricated header signal. SIEM filters can
	// page differently on each.
	| "kid_expired";

/**
 * Thrown by {@link verifyJwt} on any verification failure. The `reason` field
 * is the audit-stable discriminator; `message` is a human-readable summary
 * suitable for `logger.warn` but NOT for client-facing error responses
 * (callers must map to RFC-compliant error envelopes themselves).
 */
export class JwtVerificationError extends Error {
	override readonly name = "JwtVerificationError";
	constructor(
		readonly reason: JwtVerificationReason,
		message: string,
	) {
		super(message);
	}
}

export interface JwtVerifyOptions {
	/** Token type — selects default `typ` expectation. */
	readonly type: JwtType;
	/**
	 * Required `iss` claim — exact match. Pass an empty string to skip iss
	 * pinning when the operator has not configured `oauth.jwt.issuer` and
	 * the call site has no other source of expected issuer; the verifier
	 * emits a `jwt_verify_iss_skipped` warning so the gap is audit-visible.
	 */
	readonly expectedIssuer: string;
	/**
	 * Required `aud` claim — must be present (string) or contain (array).
	 *
	 * Optional only because bearer-as-credential routes (introspect Bearer
	 * self-intro, /userinfo, /logout id_token_hint) cannot establish the
	 * calling-client identity *before* JWT verification, so the audience to
	 * pin against is unknown at the verify call. At those sites the caller
	 * passes `undefined`; the verifier emits a `jwt_verify_aud_skipped`
	 * warning so the gap is audit-visible. All sites that DO know the
	 * calling client (token / refresh / federation / token-exchange) MUST
	 * supply this.
	 */
	readonly expectedAudience?: string | readonly string[];
	/**
	 * Optional `azp` claim binding. When provided, `payload.azp` must equal
	 * this value or verification fails with `reason: "azp"`. Used by refresh
	 * token verification to bind the RT to the authorized party (D-6 PB-2).
	 */
	readonly expectedAzp?: string;
	/**
	 * Optional `nonce` claim binding. Used by id_token verification to bind
	 * the token to the original authorization request (PB-4+5).
	 */
	readonly expectedNonce?: string;
	/**
	 * Clock skew tolerance in milliseconds applied to `exp`/`nbf`/`iat`
	 * checks. Default: 300_000 (5 min) per RFC 8725 §3.10 guidance.
	 */
	readonly clockSkewMs?: number;
	/**
	 * Override default `typ` for this {@link JwtType}. Pass `null` to skip
	 * `typ` checking entirely (legacy migration paths only).
	 */
	readonly expectedTyp?: string | null;
	/**
	 * Override expected algorithms passed to jose. Default: `[keyStore.algorithm]`.
	 * Setting an explicit list is required when verifying tokens issued by an
	 * upstream provider whose alg differs from the local KeyStore.
	 */
	readonly expectedAlgs?: readonly string[];
	/**
	 * Audit logger. All rejection paths emit a structured warn record with
	 * `{reason, jti, sub, iss, typ}` bindings so SIEM filters can index by
	 * reason without scraping message text. Optional — when absent the
	 * rejection is silent (caller handles it via the thrown error).
	 */
	readonly logger?: Logger;
	/**
	 * v0.5.1 transition: when `true` (default), tokens whose `typ` header is
	 * absent are accepted with a `jwt_verify_legacy_typ` warning. Set to
	 * `false` in v0.6+ to enforce typ presence on all tokens.
	 */
	readonly legacyTypAccept?: boolean;
}

export interface VerifiedJwt {
	readonly payload: JoseJWTPayload;
	readonly header: ProtectedHeaderParameters;
	readonly type: JwtType;
}

const DEFAULT_TYP_BY_TYPE: Record<JwtType, string> = {
	access_token: "at+jwt",
	refresh_token: "rt+jwt",
	id_token: "id+jwt",
};

const DEFAULT_CLOCK_SKEW_MS = 300_000;

/**
 * Centralized JWT verification with alg / iss / aud / typ pinning.
 *
 * The verifier:
 *  1. decodes the protected header (without signature check) to read `kid`
 *     and `typ`,
 *  2. validates `typ` against the expected value (legacy compat is opt-in
 *     via {@link JwtVerifyOptions.legacyTypAccept}),
 *  3. resolves the verification key by `kid` via
 *     {@link KeyStore.getVerificationKey} (falls back to the current signing
 *     kid when the JWT has no `kid` header),
 *  4. delegates to jose `jwtVerify` with explicit `algorithms`, `issuer`, and
 *     `audience` options — pinning all three at the security-critical layer,
 *  5. enforces `iat <= now + clockSkewMs` post-signature (jose does not
 *     validate `iat`-in-future by default), and
 *  6. enforces optional `azp` / `nonce` claim bindings post-signature.
 *
 * On any failure the verifier throws {@link JwtVerificationError} with a
 * stable {@link JwtVerificationReason}. Callers map that to their own error
 * envelope (e.g. RFC 6749 `error: "invalid_token"`).
 */
export async function verifyJwt(
	jwt: string,
	keyStore: KeyStore,
	options: JwtVerifyOptions,
): Promise<VerifiedJwt> {
	const {
		type,
		expectedIssuer,
		expectedAudience,
		expectedAzp,
		expectedNonce,
		clockSkewMs = DEFAULT_CLOCK_SKEW_MS,
		expectedTyp,
		expectedAlgs,
		logger,
		legacyTypAccept = true,
	} = options;

	let header: ProtectedHeaderParameters;
	try {
		header = decodeProtectedHeader(jwt);
	} catch {
		const err = new JwtVerificationError("signature", "JWT header decode failed");
		emitRejection(logger, err, undefined, undefined);
		throw err;
	}

	// typ check — header-only, runs before signature as a cheap token-type-
	// confusion screen. typ is in the public protected header (not part of
	// the signed claims set), so checking it pre-signature is a no-op for an
	// attacker who controls the header but not the key; it does NOT add a
	// timing oracle since rejecting on typ short-circuits before the HMAC /
	// RSA op the attacker would otherwise time. Pre-signature placement also
	// short-circuits id_token / logout_token tokens reaching an at+jwt-only
	// route (they would still fail signature against the same KeyStore, but
	// failing here keeps the audit log honest about *why*).
	const effectiveExpectedTyp = expectedTyp === undefined ? DEFAULT_TYP_BY_TYPE[type] : expectedTyp;
	if (effectiveExpectedTyp !== null) {
		const headerTyp = header.typ;
		if (headerTyp === undefined) {
			if (legacyTypAccept) {
				logger?.warn(
					{
						reason: "typ",
						typ: undefined,
						expectedTyp: effectiveExpectedTyp,
					},
					"jwt_verify_legacy_typ",
				);
			} else {
				const err = new JwtVerificationError(
					"typ",
					`JWT typ header is required (expected ${effectiveExpectedTyp})`,
				);
				emitRejection(logger, err, undefined, header);
				throw err;
			}
		} else if (headerTyp !== effectiveExpectedTyp) {
			const err = new JwtVerificationError(
				"typ",
				`JWT typ ${headerTyp} does not match expected ${effectiveExpectedTyp}`,
			);
			emitRejection(logger, err, undefined, header);
			throw err;
		}
	}

	// kid resolution — fall back to current signing kid when the JWT has no
	// kid header (back-compat with tokens signed before kid was emitted).
	const requestedKid = header.kid ?? keyStore.getSigningKidFallback();
	let verificationKey: Awaited<ReturnType<KeyStore["getVerificationKey"]>>;
	try {
		verificationKey = await keyStore.getVerificationKey(requestedKid);
	} catch (cause) {
		// IH-9 KeyStore distinguishes the two failure modes by message
		// prefix (`Expired kid:` vs `Unknown kid:`). Surface them as separate
		// reasons so SIEM pipelines can tell operator-rotation expiry apart
		// from attacker-fabricated header values.
		const causeMessage = cause instanceof Error ? cause.message : String(cause);
		const reason: JwtVerificationReason = causeMessage.startsWith("Expired kid:")
			? "kid_expired"
			: "kid_unknown";
		const err = new JwtVerificationError(reason, causeMessage);
		emitRejection(logger, err, undefined, header);
		throw err;
	}

	const algorithms = expectedAlgs ?? [keyStore.algorithm];
	const clockSkewSeconds = Math.floor(clockSkewMs / 1000);

	// Audience pinning is OPT-IN. When the caller cannot establish the
	// expected audience before verification (introspect Bearer self-intro,
	// /userinfo, /logout id_token_hint — bearer-as-credential routes), the
	// jose `audience` option is omitted and the gap is logged so the audit
	// trail records that the aud check was deliberately skipped at this
	// site rather than silently bypassed.
	const audienceForJose: string | string[] | undefined =
		expectedAudience === undefined
			? undefined
			: typeof expectedAudience === "string"
				? expectedAudience
				: [...expectedAudience];
	if (expectedAudience === undefined) {
		logger?.warn({ reason: "aud", iss: expectedIssuer, type }, "jwt_verify_aud_skipped");
	}
	// Issuer pinning is normally required, but operators who haven't
	// configured `oauth.jwt.issuer` (e.g. partial-config test fixtures, dev
	// composition roots) still need verification to function. Empty-string
	// expectedIssuer is the explicit skip — different from passing a real
	// expected issuer so it's auditable.
	const skipIssuer = expectedIssuer === "";
	if (skipIssuer) {
		logger?.warn({ reason: "iss", type }, "jwt_verify_iss_skipped");
	}

	let payload: JoseJWTPayload;
	try {
		const result = await jwtVerify(jwt, verificationKey, {
			algorithms: [...algorithms],
			...(skipIssuer ? {} : { issuer: expectedIssuer }),
			...(audienceForJose !== undefined ? { audience: audienceForJose } : {}),
			clockTolerance: clockSkewSeconds,
		});
		payload = result.payload;
	} catch (cause) {
		const reason = classifyJoseError(cause);
		const err = new JwtVerificationError(
			reason,
			cause instanceof Error ? cause.message : String(cause),
		);
		emitRejection(logger, err, undefined, header);
		throw err;
	}

	// iat in future beyond skew — jose does not enforce this; RFC 8725 §3.10
	// recommends rejecting because a future iat indicates clock tampering or
	// token replay from a forged time source.
	if (typeof payload.iat === "number") {
		const nowSeconds = Math.floor(Date.now() / 1000);
		if (payload.iat > nowSeconds + clockSkewSeconds) {
			const err = new JwtVerificationError(
				"not_yet_valid",
				`JWT iat ${payload.iat} is in the future beyond clock skew`,
			);
			emitRejection(logger, err, payload, header);
			throw err;
		}
	}

	if (expectedAzp !== undefined && payload.azp !== expectedAzp) {
		const err = new JwtVerificationError(
			"azp",
			`JWT azp ${String(payload.azp)} does not match expected ${expectedAzp}`,
		);
		emitRejection(logger, err, payload, header);
		throw err;
	}

	if (expectedNonce !== undefined && payload.nonce !== expectedNonce) {
		const err = new JwtVerificationError("nonce", `JWT nonce mismatch (expected ${expectedNonce})`);
		emitRejection(logger, err, payload, header);
		throw err;
	}

	return { payload, header, type };
}

function classifyJoseError(cause: unknown): JwtVerificationReason {
	if (cause instanceof joseErrors.JWTExpired) {
		return "expired";
	}
	if (cause instanceof joseErrors.JOSEAlgNotAllowed) {
		return "alg";
	}
	if (cause instanceof joseErrors.JWTClaimValidationFailed) {
		switch (cause.claim) {
			case "iss":
				return "iss";
			case "aud":
				return "aud";
			case "nbf":
			case "iat":
				return "not_yet_valid";
			case "exp":
				return "expired";
			default:
				// Unrecognized claim validation — fall through to generic
				// signature reason rather than invent a new bucket.
				return "signature";
		}
	}
	if (cause instanceof joseErrors.JWSSignatureVerificationFailed) {
		return "signature";
	}
	if (cause instanceof joseErrors.JWSInvalid || cause instanceof joseErrors.JWTInvalid) {
		return "signature";
	}
	return "signature";
}

function emitRejection(
	logger: Logger | undefined,
	err: JwtVerificationError,
	payload: JoseJWTPayload | undefined,
	header: ProtectedHeaderParameters | undefined,
): void {
	if (!logger) return;
	logger.warn(
		{
			reason: err.reason,
			jti: payload?.jti,
			sub: payload?.sub,
			iss: payload?.iss,
			typ: header?.typ,
		},
		"jwt_verify_rejected",
	);
}
