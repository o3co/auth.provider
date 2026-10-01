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
import { auditErrorText } from "../errors/envelope.mjs";
import { ExpiredKidError, type KeyStore, UnknownKidError } from "../keys/KeyStore.mjs";
import { isWellFormedKid, MAX_KID_LENGTH } from "../keys/kid.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { isError, lineSafeText, thrownText } from "../logging/loggableError.mjs";
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
	// The keystore could not answer the lookup: it threw something other than
	// the `UnknownKidError` / `ExpiredKidError` its contract uses for the two
	// findings — a remote key service that timed out, a vault that refused
	// the connection. An outage, like `revocation_unavailable`, and never
	// `kid_unknown`: that reason says the header named a key nobody holds,
	// and every caller answers it as the client's fault.
	| "verification_key_unavailable"
	// A revocation finding: the jti is on the AccessTokenDenylist (RFC 7009),
	// the token's `iat` is at or before the subject's revocation watermark, or
	// a watermark is in force and the token has no `iat` (it cannot prove it
	// postdates a credential change). Distinct from `expired` so SIEM can tell
	// expiry from revocation. A store that could not be consulted is
	// `revocation_unavailable`, never this.
	| "revoked"
	// A revocation store (subject watermark or jti denylist) could not be
	// consulted. Still fails closed, but as an outage, not a finding:
	// `emitRejection` logs this reason, and a shared reason would make a
	// backend blip read as a revocation of every token. Callers answer this and
	// `verification_key_unavailable` with `503` (`isVerificationUnavailable`).
	// An `invalid_grant` from the refresh grant would make the client discard
	// its refresh token (RFC 6749 §5.2), logging out every user who refreshed
	// during the outage.
	| "revocation_unavailable";

/** The longest jose message a verdict keeps: the cap `auditErrorText` applies to caller text. */
const JOSE_MESSAGE_MAX_LENGTH = 200;

/**
 * Thrown by {@link verifyJwt} on any verification failure. The `reason` field
 * is the audit-stable discriminator; `message` is a human-readable summary
 * suitable for `logger.warn` — what it quotes of the caller's token (a `typ`,
 * a `crit` name jose quotes) is on one line and capped — but NOT for
 * client-facing error responses (callers must map to RFC-compliant error
 * envelopes themselves).
 */
export class JwtVerificationError extends Error {
	override readonly name = "JwtVerificationError";
	constructor(
		readonly reason: JwtVerificationReason,
		message: string,
		options?: ErrorOptions,
	) {
		super(message, options);
	}
}

/**
 * The reasons that report an outage — a dependency the verifier could not
 * consult — rather than a finding about the token.
 */
export type VerificationUnavailableReason =
	| "verification_key_unavailable"
	| "revocation_unavailable";

/**
 * Whether `err` is a {@link JwtVerificationError} reporting an outage: the
 * keystore could not answer (`verification_key_unavailable`) or a revocation
 * store could not be consulted (`revocation_unavailable`). One predicate, so a
 * caller need not know which dependency was down.
 *
 * Every caller answers it `503 temporarily_unavailable`, never with a verdict
 * on the token: `invalid_token` (RFC 6750 §3.1), `invalid_grant` (RFC 6749
 * §5.2) and `active: false` (RFC 7662) each send the client to replace a
 * credential that may be perfectly good, into the same outage. The token is
 * still refused.
 */
export function isVerificationUnavailable(
	err: unknown,
): err is JwtVerificationError & { readonly reason: VerificationUnavailableReason } {
	return (
		err instanceof JwtVerificationError &&
		(err.reason === "verification_key_unavailable" || err.reason === "revocation_unavailable")
	);
}

/**
 * The `error_description` a caller puts beside `temporarily_unavailable` for
 * an outage {@link isVerificationUnavailable} recognises: which dependency
 * was down, and nothing about the token.
 */
export const VERIFICATION_UNAVAILABLE_DESCRIPTION: Readonly<
	Record<VerificationUnavailableReason, string>
> = Object.freeze({
	verification_key_unavailable: "verification key unavailable",
	revocation_unavailable: "revocation store unavailable",
});

/**
 * The revocation stores a verification consults, as one bundle so a call site
 * cannot forget half of them.
 *
 * - `denylist`: `denylist.has(jti)` runs after the signature, expiry and type
 *   checks; a hit throws `reason: "revoked"`.
 * - `subjectRevocation`: a token whose `iat` is at or before the subject's
 *   watermark throws `reason: "revoked"`. The denylist revokes one token by
 *   identity; the watermark revokes every token a subject held as of a moment,
 *   which a credential change needs because a subject's jtis are not
 *   enumerable.
 *
 * Either store failing to answer throws `reason: "revocation_unavailable"`.
 * Each field stays optional: whether a store exists is the composition's
 * decision. The bundle removes only the call site's ability to not ask.
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
	 * Optional only for bearer-as-credential routes (introspect Bearer
	 * self-intro, /userinfo, /logout id_token_hint), which cannot know the
	 * calling client before verification; they pass `undefined` and the
	 * verifier warns `jwt_verify_aud_skipped`. Sites that know the calling
	 * client (token, refresh, federation, token-exchange) MUST supply it.
	 */
	readonly expectedAudience?: string | readonly string[];
	/**
	 * Optional `azp` claim binding. When provided, `payload.azp` must equal
	 * this value or verification fails with `reason: "azp"`. Used by refresh
	 * token verification to bind the RT to the authorized party.
	 */
	readonly expectedAzp?: string;
	/**
	 * Optional `nonce` claim binding. Used by id_token verification to bind
	 * the token to the original authorization request.
	 */
	readonly expectedNonce?: string;
	/**
	 * Clock skew tolerance in milliseconds applied to `exp`/`nbf`/`iat`
	 * checks. Default: 300_000 (5 min); RFC 7519 §4.1.4 puts a leeway at
	 * "usually no more than a few minutes".
	 *
	 * An access-token denylist entry (`/oauth/revoke`) is kept until `exp` plus
	 * the default only. A larger value here would accept a revoked token for
	 * the difference once its entry lapses, so keep the default wherever the
	 * denylist is consulted.
	 */
	readonly clockSkewMs?: number;
	/**
	 * Cross-replica clock allowance for the subject-revocation watermark
	 * comparison, in milliseconds. Default: 1_000.
	 *
	 * Not `clockSkewMs`: that is five minutes, sized for `exp`/`nbf`, and would
	 * refuse every token minted in the five minutes after a credential change,
	 * including the re-login the change sends the user to.
	 *
	 * The comparison is `iat <= watermark`, second-truncated and inclusive. A
	 * minting replica whose clock runs a second ahead of the watermark writer
	 * stamps `iat` past it, so tokens minted just before the change would
	 * survive; one second covers a monitored fleet's skew. The cost is
	 * one-sided: a token minted within the allowance after a reset is refused,
	 * costing one retry. `0` gives the exact comparison.
	 *
	 * Rounded up to whole seconds (truncating would weaken the guard). A
	 * negative value is clamped to `0`: it would let pre-revocation tokens
	 * through.
	 */
	readonly subjectRevocationSkewMs?: number;
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
	 * Accepts tokens with no `typ` header, with a `jwt_verify_legacy_typ`
	 * warning, for an operator's bounded migration window from untyped tokens.
	 * Default `false`: typ-less tokens are rejected.
	 */
	readonly legacyTypAccept?: boolean;
	/**
	 * REQUIRED: what this verification consults about revocation. Required so
	 * a new call site cannot skip revocation silently by omission, and a
	 * deliberate skip is a greppable literal:
	 *
	 *   - `{ denylist?, subjectRevocation? }`: consult what the composition
	 *     wired. The shape for every surface that ACCEPTS a token as a
	 *     credential; forward both slots even when undefined, because wiring
	 *     nothing is the composition's decision, not the call site's.
	 *   - `"none"`: this call site does not ask, on principle. Correct only
	 *     where acting on a revoked token is safe: revoking it again
	 *     (idempotent), logging it out, or reading an id_token_hint.
	 */
	readonly revocation: VerifyRevocation;
	/**
	 * SECURITY GUARDRAIL: set true ONLY in the /oauth/revoke access-token path;
	 * anywhere else it bypasses token-lifetime enforcement. CI lint must
	 * restrict `ignoreExpiration: true` to the revoke handler. Default `false`.
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
	// The standard spelling: token-confusion refusal needs only "disjoint from
	// at+jwt", and strict external RPs that validate `typ` reject a nonstandard
	// one. `id+jwt` is refused as an ordinary typ mismatch.
	id_token: "JWT",
};

/**
 * Maps the legacy `payload.type` claim of tokens that predate the `typ`
 * header (a refresh token carried `type = "refresh"`) to a {@link JwtType}.
 * Unknown values map to `undefined` and pass under `legacyTypAccept`: an
 * unrecognised hint is not evidence of cross-type confusion.
 */
const LEGACY_PAYLOAD_TYPE_MAP: Record<string, JwtType> = {
	refresh: "refresh_token",
	access: "access_token",
};

export const DEFAULT_CLOCK_SKEW_MS = 300_000;

/**
 * Default watermark allowance: one second, the smallest value that covers a
 * minting replica a whole second ahead of the watermark writer (the comparison
 * is second-truncated); each extra second refuses a second of post-reset
 * logins. See `JwtVerifyOptions.subjectRevocationSkewMs`.
 */
export const DEFAULT_SUBJECT_REVOCATION_SKEW_MS = 1_000;

/**
 * Whether `cause` is the finding `name` names: an instance of the class, or —
 * when a composition holds two copies of this package, a keystore built
 * against one and the verifier from the other — an object carrying that
 * `name`. The finding errors set `name` to their own class name, and nothing
 * else in this package uses those names.
 */
const isFinding = (cause: unknown, cls: abstract new (...args: never[]) => Error, name: string) =>
	cause instanceof cls ||
	(typeof cause === "object" && cause !== null && (cause as { name?: unknown }).name === name);

/**
 * How long past a token's `exp` a record that revokes it must still be kept:
 * the tolerance with which this verifier accepts an expired token
 * ({@link DEFAULT_CLOCK_SKEW_MS}), the cross-replica allowance
 * ({@link DEFAULT_SUBJECT_REVOCATION_SKEW_MS}) and a whole second for the
 * rounding of `exp` to seconds. A denylist entry kept only until `exp`, or a
 * revoked refresh-token family kept only until its last token's `exp`,
 * leaves exactly that window in which the revoked token is accepted again.
 */
export const REVOCATION_RETENTION_ALLOWANCE_MS =
	DEFAULT_CLOCK_SKEW_MS + DEFAULT_SUBJECT_REVOCATION_SKEW_MS + 1_000;

/**
 * Centralized JWT verification with alg / iss / aud / typ pinning:
 *  1. decodes the protected header (unverified) for `kid` and `typ`,
 *  2. checks `typ` (legacy acceptance is opt-in via
 *     {@link JwtVerifyOptions.legacyTypAccept}),
 *  3. resolves the key by `kid`, or the current signing kid when absent; a
 *     keystore that cannot answer is `verification_key_unavailable`,
 *  4. runs jose `jwtVerify` with explicit `algorithms`, `issuer` and `audience`,
 *  5. rejects `iat` beyond `now + clockSkewMs` (jose does not),
 *  6. checks the optional `azp` / `nonce` bindings, then revocation.
 *
 * Failures throw {@link JwtVerificationError} with a stable
 * {@link JwtVerificationReason}, which callers map to their own envelope
 * (e.g. RFC 6750 `invalid_token`), except an outage
 * ({@link isVerificationUnavailable}), answered `503 temporarily_unavailable`.
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
		subjectRevocationSkewMs = DEFAULT_SUBJECT_REVOCATION_SKEW_MS,
		expectedTyp,
		expectedAlgs,
		logger,
		legacyTypAccept = false,
		revocation,
		ignoreExpiration = false,
	} = options;
	// "none" and an empty bundle behave identically below; the distinction is
	// for the reader, not the machine.
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

	// typ check, header-only and before the signature: a cheap token-confusion
	// screen. It adds no timing oracle (it short-circuits before the signature
	// op), and it keeps the audit log honest about why an id_token or
	// logout_token was refused at an at+jwt route.
	const effectiveExpectedTyp = expectedTyp === undefined ? DEFAULT_TYP_BY_TYPE[type] : expectedTyp;
	if (effectiveExpectedTyp !== null) {
		// The header is the client's JSON: `typ` may be any value. One that is
		// not a string is refused before any message is built from it — a
		// `{"toString": null}` would otherwise throw a TypeError here.
		const headerTyp: unknown = header.typ;
		if (headerTyp !== undefined && typeof headerTyp !== "string") {
			const err = new JwtVerificationError("typ", "JWT typ header is not a string");
			emitRejection(logger, err, undefined, header);
			throw err;
		}
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
			// Quoted sanitised and capped: the message is what a caller's log
			// carries as the projected error's `detail`, and the header is
			// whatever the caller wrote — CR/LF and ten thousand characters
			// included. A `typ` is a media type (RFC 7515 §4.1.9), an open
			// vocabulary, so there is no closed set to map it onto.
			const err = new JwtVerificationError(
				"typ",
				`JWT typ ${auditErrorText(headerTyp)} does not match expected ${effectiveExpectedTyp}`,
			);
			emitRejection(logger, err, undefined, header);
			throw err;
		}
	}

	// kid resolution; a JWT with no kid header falls back to the current
	// signing kid.
	//
	// The input is judged before the keystore is asked: a malformed `kid`
	// (`keys/kid.mts`; a present `kid: null` included) names no key this server
	// issued, so it is `kid_unknown`. Anything the keystore then throws besides
	// its two findings is about the keystore, not the input.
	const headerKid: unknown = header.kid;
	if (headerKid !== undefined && !isWellFormedKid(headerKid)) {
		const err = new JwtVerificationError(
			"kid_unknown",
			`JWT kid header is not a key id: a string of 1 to ${MAX_KID_LENGTH} characters with no control character`,
		);
		emitRejection(logger, err, undefined, header);
		throw err;
	}
	let verificationKey: Awaited<ReturnType<KeyStore["getVerificationKey"]>>;
	try {
		// The fallback is inside the classification too: a remote keystore
		// that cannot say which kid is current cannot answer either.
		verificationKey = await keyStore.getVerificationKey(
			headerKid ?? keyStore.getSigningKidFallback(),
		);
	} catch (cause) {
		// The two findings are typed (ExpiredKidError / UnknownKidError,
		// matched by class or, across package copies, by `name`) so SIEM can
		// tell rotation expiry from a fabricated header. Anything else is the
		// keystore failing to answer: `verification_key_unavailable`, with the
		// cause kept so a caller's log names the dependency.
		const expired = isFinding(cause, ExpiredKidError, "ExpiredKidError");
		if (expired || isFinding(cause, UnknownKidError, "UnknownKidError")) {
			const err = expired
				? new JwtVerificationError("kid_expired", "JWT kid names a retired key")
				: new JwtVerificationError("kid_unknown", "JWT kid names no key this keystore holds");
			emitRejection(logger, err, undefined, header);
			throw err;
		}
		const err = new JwtVerificationError(
			"verification_key_unavailable",
			"verification key lookup failed (fail-closed)",
			{ cause },
		);
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

	// ignoreExpiration: jose's `currentDate` is set 1s before the token's own
	// `exp` so its exp check passes; the unauthenticated decode only reads
	// `exp` (the signature is still checked below). This also shifts the `nbf`
	// reference, so a token with `nbf` near `exp` could be refused as
	// "not_yet_valid"; acceptable for the /oauth/revoke access-token path,
	// where issued tokens have iat ≈ nbf ≪ exp. The future-`iat` check below
	// uses Date.now() and is unaffected. SECURITY GUARDRAIL: /oauth/revoke only.
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
		// jose's text on one line and capped (`lineSafeText`): it is fixed
		// text about the token but for one thing — an unrecognised `crit`
		// entry is refused, before the signature, by quoting the name the
		// caller wrote. Not `auditErrorText`, whose RFC 6749 set would turn
		// every claim name jose quotes (`"exp" claim timestamp check failed`)
		// into `?exp?`.
		const err = new JwtVerificationError(
			reason,
			lineSafeText(thrownText(cause), JOSE_MESSAGE_MAX_LENGTH),
		);
		emitRejection(logger, err, undefined, header);
		throw err;
	}

	// Legacy cross-type guard: when a typ-less token passed under
	// `legacyTypAccept`, a legacy `payload.type` contradicting the expected
	// {@link JwtType} is refused, e.g. a typ-less RT (`type: "refresh"`)
	// presented as an access token at /userinfo.
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

	// iat in the future beyond skew: jose refuses one only when given
	// `maxTokenAge`, which is not passed.
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

	// Denylist check, after every signature / expiry / type check, so
	// `reason: "revoked"` is never emitted for a token that fails on structural
	// grounds.
	//
	// Fail closed: if `denylist.has` throws, revocation state is unknown, and
	// treating it as active would let revoked tokens through during an outage.
	// The refusal is `revocation_unavailable`, not `revoked`: `emitRejection`
	// logs the reason, not the message, so a store blip must not read as a
	// revocation of every token.
	if (denylist !== undefined) {
		const jti = typeof payload.jti === "string" ? payload.jti : undefined;
		if (jti !== undefined) {
			let isRevoked: boolean;
			try {
				isRevoked = await denylist.has(jti);
			} catch (cause) {
				// The store's error is the cause, never folded into the message:
				// a caller's log projects it (`loggableError`), and its text must
				// not ride past that as the verdict's own words.
				const err = new JwtVerificationError(
					"revocation_unavailable",
					"denylist consult failed (fail-closed)",
					{ cause },
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

	// Per-subject not-before watermark: a credential change cannot enumerate a
	// subject's jtis, so it records the moment before which none count. Same
	// fail-closed stance, outage reason and ordering as the denylist above.
	if (subjectRevocation !== undefined) {
		const sub = typeof payload.sub === "string" ? payload.sub : undefined;
		const iat = typeof payload.iat === "number" ? payload.iat : undefined;
		if (sub !== undefined) {
			let watermark: Date | null;
			try {
				watermark = await subjectRevocation.revokedBefore(sub);
			} catch (cause) {
				// Fail closed, reported as the outage it is: as `revoked` it would
				// read as a finding, and the refresh grant's `invalid_grant` would
				// log out every user who refreshed during it (RFC 6749 §5.2). The
				// store's error is the cause, never folded into the message.
				const err = new JwtVerificationError(
					"revocation_unavailable",
					"subject revocation consult failed (fail-closed)",
					{ cause },
				);
				emitRejection(logger, err, payload, header);
				throw err;
			}
			// A token with no `iat` cannot prove it postdates an in-force
			// watermark, so it is refused while one exists: every token this
			// provider mints carries `iat`, so an iat-less one is the
			// legacy/foreign shape a credential change must not keep honouring.
			// With no watermark, a missing `iat` is a non-event.
			if (watermark !== null && iat === undefined) {
				const err = new JwtVerificationError(
					"revoked",
					`JWT for subject ${sub} carries no iat to compare against an in-force ` +
						"subject revocation watermark (fail-closed)",
				);
				emitRejection(logger, err, payload, header);
				throw err;
			}
			// Inclusive on purpose: `iat` is second-truncated and replicas keep
			// independent clocks, so a token minted just before the revocation
			// often lands in the watermark's second. Killing one minted just
			// after costs a retry; letting one from just before survive is the
			// vulnerability. `subjectRevocationSkewMs` extends this to a replica
			// a full second ahead of the watermark writer.
			//
			// `ceil` so a sub-second allowance does not weaken the guard (1500ms
			// must not act as 1000ms), and clamped at zero so a negative value
			// cannot move the boundary before the watermark.
			const watermarkBoundarySeconds =
				watermark === null
					? 0
					: Math.floor(watermark.getTime() / 1000) +
						Math.max(0, Math.ceil(subjectRevocationSkewMs / 1000));
			if (watermark !== null && iat !== undefined && iat <= watermarkBoundarySeconds) {
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
	// jose raises Errors; anything else came from the key an adapter answered,
	// and asking its prototype (`instanceof`) may throw.
	if (!isError(cause)) return "signature";
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
			// The client's header, read before its signature: logged only as
			// the string it should be, sanitised and capped (`auditErrorText`).
			typ: typeof header?.typ === "string" ? auditErrorText(header.typ) : undefined,
		},
		"jwt_verify_rejected",
	);
}

/**
 * Once-per-(reason, type) memoization of audit-gap warnings
 * (`jwt_verify_aud_skipped`, `jwt_verify_iss_skipped`), so hot routes such as
 * /userinfo do not emit one per request. Keyed by Logger identity: a
 * singleton logger emits each gap once, and a fresh mock logger per test sees
 * a fresh emission.
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
