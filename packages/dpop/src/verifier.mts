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

/**
 * DPoP proof verifier — `createDPoPMechanism` factory.
 *
 * Checks, in order:
 *   1. one `DPoP` header value (`null` when absent)
 *   2. `parseProof`: structure, JWK screening, claims, `jkt` thumbprint
 *   3. alg allowlist, then signature (importJWK + jwtVerify)
 *   4. htm, then htu (both sides normalized; the expected origin is the
 *      configured `oauth.jwt.issuer`, never the request's forwarded
 *      protocol / Host)
 *   5. iat window
 *   6. server-provided nonce, when required; `ath` at a protected resource
 *   7. replay: one atomic `markSeen` on core's `ReplaySeenSet` under
 *      `dpop-proof:<jkt>`, kept for `replayTtlSeconds`
 *
 * A replay store that fails refuses the proof as the server's fault (503
 * `temporarily_unavailable`, see `DPoPError.code`), never as an invalid proof
 * and never by leaking a raw Redis error.
 */

import {
	buildCanonicalRequestUrl,
	ChallengeStorageError,
	checkCanonicalIssuer,
	DPOP_PROOF_REPLAY_SCOPE_PREFIX,
	describeIssuerRejection,
	type Logger,
	loggableError,
	type ReplaySeenSet,
	ReplaySeenSetFullError,
	type TokenBindingExtractContext,
	type TokenBindingMechanism,
} from "@o3co/auth-provider-core";
import type { Request } from "express";
import { importJWK, jwtVerify } from "jose";
import { athMatches } from "./ath.mjs";
import { DPoPError } from "./errors.mjs";
import { normalizeHtu } from "./htu-normalize.mjs";
import type { DPoPNonceIssuer } from "./nonce.mjs";
import { parseProof } from "./proof.mjs";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface DPoPMechanismOptions {
	/**
	 * The deployment's canonical issuer — `oauth.jwt.issuer`. Its **origin**
	 * (scheme, host, port) is the authority half of the `htu` every proof is
	 * checked against. Required, and required to be a canonical issuer URL.
	 *
	 * Not `req.protocol` and `Host`: `X-Forwarded-Proto` / `X-Forwarded-Host`
	 * rewrite both whenever Express `trust proxy` is on, so a caller who could
	 * reach the process past the edge would choose the value its own proof had
	 * to match. No request can move the issuer.
	 */
	readonly issuer: string;
	/**
	 * Where each accepted proof's `jti` is recorded, so the same proof is
	 * accepted once — core's `ReplaySeenSet`, the slot `private_key_jwt`
	 * client authentication and WebAuthn record their single-use values in.
	 * Records are scoped `dpop-proof:<jkt>`: the same `jti` under another key
	 * is a different proof, and no other consumer's scope can collide with
	 * one. A per-process set is correct for one replica only; replicas refuse
	 * each other's proofs only when they share the set.
	 */
	readonly replaySeenSet: ReplaySeenSet;
	/**
	 * Acceptance window for the `iat` claim in seconds.
	 * Default: 60 (1 minute).
	 */
	readonly iatWindowSeconds?: number;
	/**
	 * Allowlist of JOSE `alg` values. Proofs using any other algorithm are
	 * rejected with `alg_not_allowed`. Default: ES256, ES384, EdDSA, RS256.
	 */
	readonly algWhitelist?: readonly string[];
	/**
	 * How long, in seconds, a proof's replay record is kept. Default: 300. A
	 * positive finite number; construction refuses anything else, because
	 * every record's expiry is computed from it.
	 *
	 * MUST be at least **`2 × iatWindowSeconds + 1`**. The iat check is
	 * `Math.abs(floor(now) - iat) > W`: symmetric around `iat` and truncated to
	 * whole seconds, so a proof with `iat = T` is accepted until real time
	 * `T + W + 1` (exclusive). Its replay entry is written only after that check
	 * passes, so at real time `T - W` at the earliest, and expiry is half-open at
	 * `firstSeen + TTL` (the memory seen-set holds a record live only while
	 * `expiresAtMs > now`; Redis gets the same relative `PX` window). Covering
	 * the accepted interval needs `T - W + TTL >= T + W + 1`, i.e.
	 * `TTL >= 2W + 1`; at exactly `2W` the proof stays acceptable for up to a
	 * second after its entry dies.
	 *
	 * Below the requirement the mechanism logs `dpop_replay_ttl_below_window`
	 * (warn, with `iatWindowSeconds`, `replayTtlSeconds`, `requiredTtlSeconds`).
	 */
	readonly replayTtlSeconds?: number;
	readonly logger?: Logger;
	/**
	 * Server-provided nonce (RFC 9449 §8 / §9). Absent, no nonce is asked
	 * for and `iat` skew is the only freshness control. `"as"` asks at the
	 * token endpoint; `"as+rs"` also at protected resources — the mechanism
	 * tells the two apart by whether it was handed a bound access token.
	 * A proof without a valid nonce is refused as `use_dpop_nonce`, carrying
	 * the nonce to retry with; every accepted proof's answer carries the
	 * current nonce too, so a client learns of a rotation before it needs to.
	 */
	readonly nonce?: {
		readonly required: "as" | "as+rs";
		readonly issuer: DPoPNonceIssuer;
	};
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_ALG_WHITELIST: readonly string[] = ["ES256", "ES384", "EdDSA", "RS256"];

/**
 * The signature and MAC algorithm names in IANA's "JSON Web Signature and
 * Encryption Algorithms" registry (as of 2026-05-22): a closed vocabulary, so
 * a refused alg in it can be named on a log line without a client choosing
 * what the line says. Anything else — a JWE key-management name
 * (`RSA-OAEP`, `dir`) included — is logged as `unregistered`.
 */
const REGISTERED_JWS_ALGS: ReadonlySet<string> = new Set([
	// RFC 7518 §3.1
	"HS256",
	"HS384",
	"HS512",
	"RS256",
	"RS384",
	"RS512",
	"ES256",
	"ES384",
	"ES512",
	"PS256",
	"PS384",
	"PS512",
	"none",
	// RFC 8037 (Deprecated by RFC 9864), RFC 9864, RFC 8812
	"EdDSA",
	"Ed25519",
	"Ed448",
	"ES256K",
	// RFC 9964
	"ML-DSA-44",
	"ML-DSA-65",
	"ML-DSA-87",
	// W3C WebCrypto, registered for use in a JWK and marked Prohibited
	"RS1",
	"HS1",
]);
const DEFAULT_IAT_WINDOW_SECONDS = 60;
const DEFAULT_REPLAY_TTL_SECONDS = 300;

// A proof's `jti` is recorded under core's `DPOP_PROOF_REPLAY_SCOPE_PREFIX`:
// `dpop-proof:<jkt>`. The seen-set is shared with other consumers
// (`client-assertion:<client_id>`, `webauthn:*`, and
// `jwt-bearer:id-jag:<issuer>` where a composition hands the jwt-bearer
// verifier the same set), and its canonical key is length-prefixed, so no
// record of theirs can collide with one of these. Core owns the prefix
// because its in-process seen-set caps DPoP proofs at a share of its size.
// The scope is visible in Redis keys, and the tests pin the literal.

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// The effective request URL for htu comparison is the configured origin plus
// `req.originalUrl` (core's `buildCanonicalRequestUrl`). The origin is fixed
// at construction from `oauth.jwt.issuer`; the query string rides along
// because `normalizeHtu` strips it from both sides.

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a DPoP `TokenBindingMechanism` for use with `tokenBindingMw`. The
 * mechanism returns `null` when the `DPoP` header is absent, throws
 * `DPoPError` for any invalid proof, and returns
 * `{ kind: "dpop", confirmation: { jkt } }` on success, `jkt` being the
 * RFC 7638 thumbprint `parseProof` computed.
 */
export const createDPoPMechanism = (options: DPoPMechanismOptions): TokenBindingMechanism => {
	// The expected `htu` comes from the deployment's identity, not from the
	// request. Validate it here rather than at first use: a mechanism that
	// cannot name its own origin would fail every proof with `htu_mismatch`,
	// which reads as a client bug rather than a misconfiguration.
	const issuerRejection = checkCanonicalIssuer(options.issuer);
	if (issuerRejection !== null) {
		throw new Error(
			`createDPoPMechanism: issuer ${describeIssuerRejection(issuerRejection)}. It is the ` +
				"deployment's canonical issuer (config `oauth.jwt.issuer`), and its origin is what " +
				"every DPoP proof's `htu` is checked against — reconstructing that origin from " +
				"`req.protocol` and the `Host` header would let a caller behind a trusted proxy " +
				"choose the value its own proof has to match (o3co/auth.provider#292).",
		);
	}
	// `URL.origin` is scheme + host + port with the default port elided —
	// exactly the authority half `normalizeHtu` canonicalizes to. Any path
	// prefix on the issuer is dropped on purpose: the path belongs to the
	// request, which `req.originalUrl` already reports including that prefix.
	const issuerOrigin = new URL(options.issuer).origin;

	const algWhitelist = options.algWhitelist ?? DEFAULT_ALG_WHITELIST;
	const iatWindowSeconds = options.iatWindowSeconds ?? DEFAULT_IAT_WINDOW_SECONDS;
	const replayTtlSeconds = options.replayTtlSeconds ?? DEFAULT_REPLAY_TTL_SECONDS;
	const { replaySeenSet, logger, nonce } = options;

	// Every record's expiry is `now + replayTtlSeconds`. NaN would write a
	// record the memory seen-set never expires and hand Redis `PX NaN`; a
	// non-positive value one that is expired at issue. A composition fault
	// either way, refused where it is made rather than on every proof.
	if (!Number.isFinite(replayTtlSeconds) || replayTtlSeconds <= 0) {
		throw new RangeError(
			`createDPoPMechanism: replayTtlSeconds must be a positive finite number (got ${String(replayTtlSeconds)})`,
		);
	}

	// Replay entries must outlive the acceptance window they protect: at least
	// `2W + 1` (derivation at `DPoPMechanismOptions.replayTtlSeconds`). Warn
	// rather than throw: the failure is a weakened replay guarantee under clock
	// skew, not an unusable configuration, and refusing to construct would break
	// running deployments.
	const requiredTtlSeconds = iatWindowSeconds * 2 + 1;
	if (replayTtlSeconds < requiredTtlSeconds) {
		logger?.warn(
			{ iatWindowSeconds, replayTtlSeconds, requiredTtlSeconds },
			"dpop_replay_ttl_below_window",
		);
	}

	return {
		kind: "dpop",
		/**
		 * DPoP is explicit-intent: the client deliberately presents the `DPoP`
		 * header, so it wins over ambient mechanisms (mTLS) in `intent-explicit`
		 * dispatch mode.
		 */
		intentExplicit: true,

		extract: async (req: Request, ctx?: TokenBindingExtractContext) => {
			const header = req.get("dpop");
			if (header === undefined) {
				return null; // non-DPoP request — no binding
			}

			if (header.includes(",")) {
				throw new DPoPError("multiple_headers", "Multiple DPoP header values presented");
			}

			const proof = await parseProof(header);

			// parseProof ensures alg is a non-empty string; the allowlist is here.
			if (!algWhitelist.includes(proof.alg)) {
				// The alg is the client's: named on the line only when it is a
				// registered one, and never in the refusal's message.
				logger?.warn(
					{
						alg: REGISTERED_JWS_ALGS.has(proof.alg) ? proof.alg : "unregistered",
						whitelist: algWhitelist,
					},
					"dpop_alg_not_allowed",
				);
				throw new DPoPError("alg_not_allowed", "alg is not an accepted DPoP algorithm");
			}

			try {
				const publicKey = await importJWK(proof.jwk, proof.alg);
				await jwtVerify(header, publicKey, { typ: "dpop+jwt" });
			} catch (err) {
				// Re-throw DPoPError as-is (shouldn't happen here, but safe).
				if (err instanceof DPoPError) throw err;
				// The projection: jose puts the proof's whole payload on a
				// claim failure (`JWTExpired`, `JWTClaimValidationFailed`).
				logger?.warn({ err: loggableError(err) }, "dpop_signature_invalid");
				throw new DPoPError("signature_invalid", "DPoP proof signature verification failed");
			}

			if (proof.claims.htm.toUpperCase() !== req.method.toUpperCase()) {
				throw new DPoPError("htm_mismatch", "DPoP proof htm does not match request method", {
					expected: req.method.toUpperCase(),
					presented: proof.claims.htm,
				});
			}

			// Both sides normalized. `normalizeHtu` throws when either URL contains
			// userinfo (see there); wrap so the contract stays inside `DPoPError`.
			let expectedHtu: string;
			let presentedHtu: string;
			try {
				expectedHtu = normalizeHtu(buildCanonicalRequestUrl(issuerOrigin, req.originalUrl));
				presentedHtu = normalizeHtu(proof.claims.htu);
			} catch (err) {
				// Fixed text: the canonicalization's error is the cause, not part
				// of the message.
				throw new DPoPError(
					"malformed_proof",
					"DPoP htu canonicalization failed",
					undefined,
					undefined,
					{ cause: err },
				);
			}
			if (expectedHtu !== presentedHtu) {
				throw new DPoPError("htu_mismatch", "DPoP proof htu does not match request URI", {
					expected: expectedHtu,
					presented: presentedHtu,
				});
			}

			const nowSec = Math.floor(Date.now() / 1000);
			const drift = Math.abs(nowSec - proof.claims.iat);
			if (drift > iatWindowSeconds) {
				throw new DPoPError(
					"iat_out_of_window",
					"DPoP proof iat is outside the acceptance window",
					{
						windowSeconds: iatWindowSeconds,
						drift,
					},
				);
			}

			// The server-provided nonce, checked before the replay store is
			// consulted — a proof refused here is one the client is about to
			// present again with the nonce filled in, and it must not have spent
			// its jti. `ctx` is what a protected resource hands over; its absence
			// means the token endpoint.
			const nonceRequired =
				nonce !== undefined && (ctx === undefined || nonce.required === "as+rs");
			let currentNonce: string | undefined;
			if (nonceRequired) {
				currentNonce = nonce.issuer.issue();
				const headers = { "DPoP-Nonce": currentNonce };
				const presented = proof.claims.nonce;
				if (presented === undefined) {
					throw new DPoPError(
						"nonce_required",
						"DPoP proof carries no nonce; this server requires one",
						undefined,
						headers,
					);
				}
				if (!nonce.issuer.verify(presented)) {
					throw new DPoPError(
						"nonce_invalid",
						"DPoP proof nonce is not one this server issued within its window",
						undefined,
						headers,
					);
				}
			}

			// RFC 9449 §7.1: at a protected resource the proof MUST carry an `ath`
			// binding it to the access token it accompanies; without it, a proof
			// captured alongside one request authorises any other stolen token.
			//
			// Checked before the replay record, so a mismatched `ath` does not spend
			// the `jti`: an attacker who intercepts a proof could otherwise burn it
			// with a mismatched token and have the client's own request refused as a
			// replay.
			//
			// `ctx` absent = the token endpoint (§5), where no access token exists
			// yet; a stray `ath` there is ignored, having nothing to contradict.
			if (ctx !== undefined) {
				const { ath } = proof.claims;
				if (ath === undefined) {
					throw new DPoPError(
						"ath_missing",
						"DPoP proof presented at a protected resource has no ath claim",
					);
				}
				if (!(await athMatches(ath, ctx.boundAccessToken))) {
					// The presented and expected digests are deliberately NOT
					// attached as detail: both are derivable from material the
					// caller already holds, but echoing them turns the audit
					// record into a confirmation oracle for token guesses.
					throw new DPoPError(
						"ath_mismatch",
						"DPoP proof ath does not match the presented access token",
					);
				}
			}

			// proof.jkt is the canonical value; do not re-compute it.
			const { jkt } = proof;

			// One atomic check-and-mark of the (jkt, jti) pair: `markSeen` answers
			// true only to the call that wrote the record, so of two concurrent
			// requests carrying the same proof exactly one is accepted. The deadline
			// is absolute (Redis sends `PX` = deadline − its own now), so time spent
			// reaching the store does not shorten the record below the window.
			//
			// A transport fault (Redis ECONNREFUSED, etc.) is an outage, not a
			// verdict: `replay_store_unavailable`, answered 503
			// `temporarily_unavailable` rather than RFC 9449's `invalid_dpop_proof`,
			// and never the raw error. Either way an unrecorded proof is never
			// accepted.
			let fresh: boolean;
			try {
				fresh = await replaySeenSet.markSeen(
					`${DPOP_PROOF_REPLAY_SCOPE_PREFIX}${jkt}`,
					proof.claims.jti,
					Date.now() + replayTtlSeconds * 1000,
				);
			} catch (err) {
				// A DPoPError keeps its classification: a future refactor might
				// shape seen-set errors directly as one.
				if (err instanceof DPoPError) throw err;
				// Core's in-process set refused the write because it holds DPoP's
				// share of its cap (or is full): neither down nor broken, and named
				// apart so an operator reads a flood or an undersized cap rather
				// than a store to go and fix.
				if (err instanceof ReplaySeenSetFullError) {
					throw new DPoPError(
						"replay_store_full",
						"DPoP replay store is full; cannot record the proof",
						undefined,
						undefined,
						{ cause: err },
					);
				}
				// The seen-set's own contract errors (`expired-at-issue`, which a
				// positive TTL cannot earn, and RangeError for a non-finite expiry,
				// which construction rules out) mean the set is broken: the server's
				// fault, so the outage's answer (503, proof refused unrecorded) rather
				// than a rethrow, which core's dispatcher would answer
				// `400 invalid_dpop_proof`. `replay_store_fault` keeps triage off Redis
				// health: the fix is in the composition.
				//
				// In every case the error goes upward as the refusal's `cause` and this
				// mechanism logs nothing: core's dispatcher answering the 503 logs the
				// cause's projection, never the error, on which ioredis puts the
				// refused command, the record's key included.
				if (err instanceof ChallengeStorageError || err instanceof RangeError) {
					throw new DPoPError(
						"replay_store_fault",
						"DPoP replay store broke its own contract; cannot determine replay status",
						undefined,
						undefined,
						{ cause: err },
					);
				}
				throw new DPoPError(
					"replay_store_unavailable",
					"DPoP replay store is unavailable; cannot determine replay status",
					undefined,
					undefined,
					{ cause: err },
				);
			}
			if (!fresh) {
				throw new DPoPError(
					"replay_detected",
					"DPoP proof (jti, jkt) already seen in replay window",
					{
						jti: proof.claims.jti,
					},
				);
			}

			// The RFC 7800 `cnf.jkt` confirmation; the `proof` object is not
			// forwarded.
			return {
				kind: "dpop",
				confirmation: { jkt },
				...(currentNonce === undefined ? {} : { responseHeaders: { "DPoP-Nonce": currentNonce } }),
			};
		},
	};
};
