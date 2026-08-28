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
	decodeJwt,
	decodeProtectedHeader,
	type JWTPayload as JoseJWTPayload,
	errors as joseErrors,
	jwtVerify,
	type ProtectedHeaderParameters,
} from "jose";
import type { AccessTokenDenylist } from "../access-token-denylist/types.mjs";
import { ExpiredKidError, type KeyStore } from "../keys/KeyStore.mjs";
import type { Logger } from "../logging/Logger.mjs";
import type { SubjectRevocation } from "../user-sessions/types.mjs";

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
	| "kid_expired"
	// Wave 1 (§4.5): token present in the AccessTokenDenylist (i.e. explicitly
	// revoked via RFC 7009). Distinct from `expired` so SIEM filters can tell
	// natural expiry apart from an operator-initiated revocation event.
	| "revoked";

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

/**
 * The revocation stores that a verification consults, travelling as one
 * bundle (#367) so a call site cannot forget half of them.
 *
 * - `denylist` — Wave 1 (§4.5): `denylist.has(jti)` runs after all
 *   signature/expiry/type checks; a hit throws `reason: "revoked"`.
 * - `subjectRevocation` — #296: a token whose `iat` is at or before the
 *   subject's revocation watermark throws `reason: "revoked"`. The companion
 *   to the denylist rather than a replacement: the denylist revokes a token
 *   by identity, the watermark revokes every token a subject held as of a
 *   moment — which is what a credential change needs, since the jtis
 *   outstanding for a subject are not enumerable.
 *
 * Both fields stay individually optional inside the bundle: whether each
 * store exists is the composition's decision (#363). What the bundle removes
 * is the call site's ability to not ask.
 */
export interface JwtRevocationSources {
	readonly denylist?: AccessTokenDenylist;
	readonly subjectRevocation?: SubjectRevocation;
}

/**
 * What a `verifyJwt` call consults about revocation — the sources the
 * composition wired, or the literal `"none"` for the few surfaces where a
 * revoked token is still safe to act on. See
 * {@link JwtVerifyOptions.revocation} for when each is correct.
 */
export type VerifyRevocation = "none" | JwtRevocationSources;

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
	 * SF-1 transition flag for the v0.4.x→v0.5.x typ-header rollout.
	 *
	 * The default is `false`: tokens whose `typ` header is absent are
	 * rejected. Operators with v0.4.x tokens still in circulation can set
	 * this to `true` for their own bounded migration window — when true,
	 * typ-less tokens are accepted and emit a `jwt_verify_legacy_typ`
	 * warning. The v0.5.x default was `true`; Phase G S2 flips it.
	 */
	readonly legacyTypAccept?: boolean;
	/**
	 * REQUIRED: what this verification consults about revocation (#367).
	 *
	 * The two checks used to be independent optional options whose omission
	 * "preserved current behavior" — which meant a new call site skipped
	 * revocation silently, the same seam shape that produced the #277/#287/
	 * #322 silent no-ops. Ten call sites hand-forwarded them; the eleventh
	 * would have failed open with no symptom. Making the field required turns
	 * that omission into a type error, and makes the deliberate skip a
	 * greppable, reviewable literal:
	 *
	 *   - `{ denylist?, subjectRevocation? }` — consult what the composition
	 *     wired. This is the shape for every surface that ACCEPTS a token as
	 *     a credential; forward both slots even when they may be undefined,
	 *     because "the deployment wired nothing" is the composition's
	 *     decision (#363), not the call site's.
	 *   - `"none"` — this call site does not ask about revocation ON
	 *     PRINCIPLE, and says so in a code review-able way. Correct only
	 *     where the operation is safe or meaningful for a revoked token:
	 *     revoking it again (idempotent), logging it out, or reading an
	 *     id_token_hint.
	 */
	readonly revocation: VerifyRevocation;
	/**
	 * Wave 1 (§4.5): SECURITY GUARDRAIL — set true ONLY in the /oauth/revoke
	 * AT path. Spreading this flag to other call sites bypasses token-lifetime
	 * enforcement. CI lint must restrict `ignoreExpiration: true` to revoke handler.
	 *
	 * Default: `false` (exp check runs as normal).
	 */
	readonly ignoreExpiration?: boolean;
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

/**
 * Maps the v0.3-era `payload.type` legacy claim back to a {@link JwtType}.
 * v0.3 tokens predated the `typ` header convention; refresh tokens emitted
 * `payload.type = "refresh"` instead. Unknown values map to `undefined`
 * (the verifier accepts them under `legacyTypAccept` rather than rejecting,
 * matching the philosophy that an unrecognized legacy hint is not evidence
 * of cross-type confusion).
 */
const LEGACY_PAYLOAD_TYPE_MAP: Record<string, JwtType> = {
	refresh: "refresh_token",
	access: "access_token",
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
		legacyTypAccept = false,
		revocation,
		ignoreExpiration = false,
	} = options;
	// "none" and an empty bundle behave identically below; the distinction is
	// for the reader and the reviewer, not the machine.
	const denylist = revocation === "none" ? undefined : revocation.denylist;
	const subjectRevocation = revocation === "none" ? undefined : revocation.subjectRevocation;

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
		// KeyStore distinguishes the two failure modes via typed errors
		// (ExpiredKidError / UnknownKidError) so SIEM pipelines can tell
		// operator-rotation expiry apart from attacker-fabricated header
		// values without coupling to message text.
		const reason: JwtVerificationReason =
			cause instanceof ExpiredKidError ? "kid_expired" : "kid_unknown";
		const message = cause instanceof Error ? cause.message : String(cause);
		const err = new JwtVerificationError(reason, message);
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
		// Once-per-(logger, reason, type) so /userinfo and other hot bearer-as-
		// credential routes don't flood ingestion with a warn record per request.
		// Operators see the gap on first occurrence; volume signal is preserved
		// in route-level request counters, not the audit log.
		warnAuditGapOnce(logger, "aud", type, { iss: expectedIssuer }, "jwt_verify_aud_skipped");
	}
	// Issuer pinning is normally required, but operators who haven't
	// configured `oauth.jwt.issuer` (e.g. partial-config test fixtures, dev
	// composition roots) still need verification to function. Empty-string
	// expectedIssuer is the explicit skip — different from passing a real
	// expected issuer so it's auditable.
	const skipIssuer = expectedIssuer === "";
	if (skipIssuer) {
		warnAuditGapOnce(logger, "iss", type, {}, "jwt_verify_iss_skipped");
	}

	// ignoreExpiration: when true, pass a currentDate set to 1 second before
	// the token's own exp so jose's exp check always passes. We decode the
	// payload (unauthenticated, signature checked in the jwtVerify call below)
	// purely to read the numeric exp claim.
	//
	// CAVEAT: this also shifts the reference for nbf validation — jose checks
	// `nbf > currentDate + tolerance` against the same currentDate. A token
	// with nbf set close to exp (legal but unusual) could be wrongly rejected
	// with reason "not_yet_valid" when ignoreExpiration is true. This is
	// acceptable for the /oauth/revoke AT path because issued access tokens
	// always have iat ≈ nbf ≪ exp. iat-future check (post-signature, below)
	// uses Date.now() directly and is unaffected.
	//
	// SECURITY GUARDRAIL: use only in the /oauth/revoke AT path (§4.5).
	let ignoreExpirationCurrentDate: Date | undefined;
	if (ignoreExpiration) {
		try {
			const rawPayload = decodeJwt(jwt);
			if (typeof rawPayload.exp === "number") {
				// Set currentDate to exp - 1s so exp check passes exactly.
				ignoreExpirationCurrentDate = new Date((rawPayload.exp - 1) * 1000);
			}
		} catch {
			// If decodeJwt fails, fall through — jwtVerify will reject the JWT
			// anyway (malformed), so skipping exp-bypass is safe.
		}
	}

	let payload: JoseJWTPayload;
	try {
		const result = await jwtVerify(jwt, verificationKey, {
			algorithms: [...algorithms],
			...(skipIssuer ? {} : { issuer: expectedIssuer }),
			...(audienceForJose !== undefined ? { audience: audienceForJose } : {}),
			clockTolerance: clockSkewSeconds,
			...(ignoreExpirationCurrentDate !== undefined
				? { currentDate: ignoreExpirationCurrentDate }
				: {}),
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

	// Legacy cross-type acceptance guard (Copilot review): when the header
	// `typ` was absent and `legacyTypAccept` waved through the typ check,
	// a v0.3-era token whose `payload.type` claim contradicts the expected
	// {@link JwtType} would otherwise pass — e.g. a typ-less RT carrying
	// `payload.type: "refresh"` accepted as an access token at /userinfo.
	// Map the legacy claim back to the type universe and reject contradictions.
	if (header.typ === undefined && typeof payload.type === "string") {
		const mappedType = LEGACY_PAYLOAD_TYPE_MAP[payload.type];
		if (mappedType !== undefined && mappedType !== type) {
			const err = new JwtVerificationError(
				"typ",
				`JWT legacy payload.type ${payload.type} maps to ${mappedType}, expected ${type}`,
			);
			emitRejection(logger, err, payload, header);
			throw err;
		}
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

	// Wave 1 (§4.5): denylist check — runs after all signature/expiry/type checks
	// so revocation is only consulted for otherwise-valid tokens. This ordering
	// ensures `reason: "revoked"` is never emitted for tokens that would already
	// fail on structural grounds (expired, wrong typ, etc.) — keeping the audit
	// signal crisp.
	//
	// Fail-closed on denylist backend errors: if `denylist.has` throws (e.g.
	// Redis network failure), we cannot determine revocation state. Treating
	// "unknown" as "active" would let revoked tokens through during outages;
	// secure default is to reject with `reason: "revoked"` and emit an audit
	// event capturing the underlying cause so operators can distinguish a true
	// revocation from a backend outage in logs/metrics.
	if (denylist !== undefined) {
		const jti = typeof payload.jti === "string" ? payload.jti : undefined;
		if (jti !== undefined) {
			let isRevoked: boolean;
			try {
				isRevoked = await denylist.has(jti);
			} catch (cause) {
				const causeMessage = cause instanceof Error ? cause.message : String(cause);
				const err = new JwtVerificationError(
					"revoked",
					`denylist consult failed (fail-closed): ${causeMessage}`,
				);
				emitRejection(logger, err, payload, header);
				throw err;
			}
			if (isRevoked) {
				const err = new JwtVerificationError(
					"revoked",
					`JWT jti ${jti} is in the revocation denylist`,
				);
				emitRejection(logger, err, payload, header);
				throw err;
			}
		}
	}

	// #296: per-subject not-before watermark. A credential change cannot
	// enumerate the jtis a subject currently holds, so it records the moment
	// before which none of them count and this consults it.
	//
	// Same fail-closed stance and same ordering rationale as the denylist above:
	// an unreachable backend must not read as "not revoked", and the check runs
	// only for otherwise-valid tokens so `reason: "revoked"` stays crisp.
	if (subjectRevocation !== undefined) {
		const sub = typeof payload.sub === "string" ? payload.sub : undefined;
		const iat = typeof payload.iat === "number" ? payload.iat : undefined;
		if (sub !== undefined && iat !== undefined) {
			let watermark: Date | null;
			try {
				watermark = await subjectRevocation.revokedBefore(sub);
			} catch (cause) {
				const causeMessage = cause instanceof Error ? cause.message : String(cause);
				const err = new JwtVerificationError(
					"revoked",
					`subject revocation consult failed (fail-closed): ${causeMessage}`,
				);
				emitRejection(logger, err, payload, header);
				throw err;
			}
			// Inclusive on purpose. `iat` is second-truncated and a multi-replica
			// deployment has independent clocks, so a token minted a few hundred
			// milliseconds *before* the revocation routinely lands in the same
			// second as the watermark. Killing one minted just after costs a
			// retry; letting one from just before survive is the vulnerability.
			if (watermark !== null && iat <= Math.floor(watermark.getTime() / 1000)) {
				const err = new JwtVerificationError(
					"revoked",
					`JWT for subject ${sub} predates the subject revocation watermark`,
				);
				emitRejection(logger, err, payload, header);
				throw err;
			}
		}
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

/**
 * Per-logger once-per-(reason, type) memoization for audit-gap warnings
 * (`jwt_verify_aud_skipped`, `jwt_verify_iss_skipped`). Hot bearer-as-
 * credential routes (e.g. /userinfo) would otherwise emit one warn record
 * per request — operationally noisy and a real ingestion-cost issue.
 *
 * The map is keyed by Logger identity so each unique logger instance gets
 * its own dedupe set: production deployments with a singleton logger emit
 * each gap exactly once; tests that construct fresh mock loggers per case
 * see a fresh emission per test (so assertions on warn calls remain
 * deterministic). WeakMap auto-clears on logger GC.
 */
const auditGapEmitted = new WeakMap<Logger, Set<string>>();

function warnAuditGapOnce(
	logger: Logger | undefined,
	reason: "aud" | "iss",
	type: JwtType,
	bindings: Record<string, unknown>,
	msg: string,
): void {
	if (!logger) return;
	let seen = auditGapEmitted.get(logger);
	if (!seen) {
		seen = new Set<string>();
		auditGapEmitted.set(logger, seen);
	}
	const key = `${reason}:${type}`;
	if (seen.has(key)) return;
	seen.add(key);
	logger.warn({ reason, type, ...bindings }, msg);
}
