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
 * Implements the RFC 9449 §6 validation sequence (15 steps) for the
 * token endpoint. Step ordering follows the spec's taxonomy:
 *
 *   Step 1:  DPoP header presence check  (null when absent)
 *   Step 2:  Single header value         (throw on comma)
 *   Steps 3–9, 13: parseProof (structural + JWK + claims + jkt thumbprint)
 *   Step 5:  alg whitelist               (after parseProof, uses proof.alg)
 *   Step 8:  Signature verification      (importJWK + jwtVerify)
 *   Step 10: htm match
 *   Step 11: htu match (both sides normalized). The expected URL's origin is
 *            the configured `oauth.jwt.issuer`, never the request's forwarded
 *            protocol / Host (#292).
 *   Step 12: iat window
 *   Step 14: Replay check (atomic seen) — wrapped so transport faults
 *            surface as `replay_store_unavailable` audit signal rather
 *            than leaking raw Redis errors through `tokenBindingMw`.
 *   Step 15: Return TokenBinding
 *
 * The verifier relies on `parseProof` (Sub-PR 2a) for steps 3–9 + 13 and
 * reuses the `jkt` already computed there (no re-derive in this layer).
 *
 * Per Wave 2 Phase 2 spec §6 + §8 factory contract.
 */

import {
	checkCanonicalIssuer,
	describeIssuerRejection,
	type Logger,
	type TokenBindingExtractContext,
	type TokenBindingMechanism,
} from "@o3co/auth-provider-core";
import type { Request } from "express";
import { importJWK, jwtVerify } from "jose";
import { athMatches } from "./ath.mjs";
import { DPoPError } from "./errors.mjs";
import { normalizeHtu } from "./htu-normalize.mjs";
import { parseProof } from "./proof.mjs";
import type { DPoPReplayStore } from "./replay-store.mjs";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface DPoPMechanismOptions {
	/**
	 * The deployment's canonical issuer — `oauth.jwt.issuer`. Its **origin**
	 * (scheme, host, port) is the authority half of the `htu` every proof is
	 * checked against.
	 *
	 * Required, and required to be a canonical issuer URL (#292). Before that
	 * the expected `htu` was reconstructed from `req.protocol` and the `Host`
	 * header, both of which `X-Forwarded-Proto` / `X-Forwarded-Host` rewrite
	 * whenever Express `trust proxy` is on — so a caller who could reach the
	 * process past the edge chose the value its own proof had to match, and
	 * satisfied both halves of the comparison at once. The issuer is a property
	 * of the deployment and cannot be moved by a request, which is the whole
	 * reason it is the right source. Same reasoning as #266/#307, which stopped
	 * deriving `iss` from `Host`.
	 */
	readonly issuer: string;
	/** Replay protection store. */
	readonly replayStore: DPoPReplayStore;
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
	 * TTL in seconds for replay entries in the store. Default: 300 (5 minutes).
	 *
	 * MUST be at least **`2 × iatWindowSeconds + 1`**, not `iatWindowSeconds`.
	 *
	 * The `iat` check is `Math.abs(now - iat) > iatWindowSeconds` against
	 * `now = Math.floor(Date.now() / 1000)`, so the acceptance window is
	 * symmetric around `iat` AND truncated to whole seconds: a proof with
	 * `iat = T` keeps being accepted while `floor(now) <= T + W`, i.e. until
	 * real time `T + W + 1` (exclusive) — very nearly a second past `T + W`.
	 *
	 * A replay entry is written only after the window check passes (step 14
	 * follows step 12), so the earliest it can be created is real time
	 * `T - W`, and it expires at `firstSeen + TTL`. Expiry is half-open — the
	 * memory store treats an entry as live only while `expiry > now` — so the
	 * entry is already gone at `firstSeen + TTL`.
	 *
	 * Covering the whole accepted interval therefore requires
	 * `T - W + TTL >= T + W + 1`, i.e. `TTL >= 2W + 1`. At exactly `2W` the
	 * entry dies at `T + W` while the proof stays acceptable for up to another
	 * second — a real, if narrow, replay window.
	 *
	 * The defaults (60 / 300) satisfy this with margin. A mechanism
	 * constructed below the requirement logs a warning
	 * (`reason: "replay_ttl_below_iat_window"`, carrying `requiredTtlSeconds`).
	 */
	readonly replayTtlSeconds?: number;
	readonly logger?: Logger;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_ALG_WHITELIST: readonly string[] = ["ES256", "ES384", "EdDSA", "RS256"];
const DEFAULT_IAT_WINDOW_SECONDS = 60;
const DEFAULT_REPLAY_TTL_SECONDS = 300;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Build the effective request URL for htu comparison: the deployment's
 * **configured** origin plus the path the request actually reached.
 *
 * The origin is fixed at construction from `oauth.jwt.issuer` and is
 * deliberately not derived from the request. `req.protocol` and `req.get("host")`
 * read `X-Forwarded-Proto` / `X-Forwarded-Host` under Express `trust proxy`,
 * so reconstructing from them let the caller pick the value its own proof had
 * to match (#292).
 *
 * The path still comes from `req.originalUrl` — the AS serves whatever path it
 * is mounted at, and the query string rides along because `normalizeHtu`
 * strips it uniformly from both sides.
 *
 * String concatenation, never `new URL(path, origin)`: a request target of
 * `//evil.example/token` resolves *relative to* an origin as a
 * protocol-relative URL and would move the host, which is the same spoof
 * arriving through a different door. Concatenated onto an absolute origin the
 * WHATWG parser reads it as the path it is.
 */
const buildRequestUrl = (issuerOrigin: string, req: Request): string => {
	const target = req.originalUrl;
	// Express reports an origin-form target, which always starts with `/`. An
	// absolute-form target (`GET http://x/ HTTP/1.1`, legal per RFC 9112 §3.2)
	// would not, and must not be spliced into the authority position.
	const path = target.startsWith("/") ? target : `/${target}`;
	return `${issuerOrigin}${path}`;
};

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a DPoP `TokenBindingMechanism` for use with `tokenBindingMw`.
 *
 * The returned mechanism:
 *   - Returns `null` when the `DPoP` header is absent (non-DPoP request).
 *   - Throws `DPoPError` for any proof invalidity.
 *   - Returns `{ kind: "dpop", confirmation: { jkt } }` on success.
 *
 * The `jkt` in the confirmation is the RFC 7638 SHA-256 thumbprint of the
 * proof's JWK, computed by `parseProof` (Sub-PR 2a) — not re-derived here.
 *
 * Per Wave 2 Phase 2 spec §8 (factory contract) + §6 (validation sequence).
 */
export const createDPoPMechanism = (options: DPoPMechanismOptions): TokenBindingMechanism => {
	// #292: the expected `htu` comes from the deployment's identity, not from
	// the request. Validate it here rather than at first use — a mechanism that
	// cannot name its own origin would otherwise fail every proof at runtime
	// with `htu_mismatch`, which reads as a client bug rather than a
	// misconfiguration.
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
	const { replayStore, logger } = options;

	// Replay entries must outlive the acceptance window they protect. The iat
	// check is symmetric AND second-truncated (`Math.abs(floor(now) - iat) > W`),
	// so a proof stays acceptable until real time `T + W + 1` (exclusive),
	// while its entry starts at first sighting — possibly the earliest edge,
	// `T - W` — and expires half-open at `firstSeen + TTL`. Hence `2W + 1`,
	// not `2W`: at exactly `2W` the entry dies a second early. See the
	// `replayTtlSeconds` docs for the derivation.
	// Warn rather than throw: the failure is a weakened replay guarantee under
	// clock skew, not an unusable configuration, and refusing to construct
	// would break deployments that are running today.
	const requiredTtlSeconds = iatWindowSeconds * 2 + 1;
	if (replayTtlSeconds < requiredTtlSeconds) {
		logger?.warn(
			{
				reason: "replay_ttl_below_iat_window",
				iatWindowSeconds,
				replayTtlSeconds,
				requiredTtlSeconds,
			},
			"replayTtlSeconds is below 2x iatWindowSeconds; a proof can outlive its replay entry and be replayed while still inside its acceptance window",
		);
	}

	return {
		kind: "dpop",
		/**
		 * `true` — DPoP is an explicit application-layer construction: the
		 * client intentionally presents the `DPoP` header. Per cluster spec
		 * §3.5, explicit-intent mechanisms win over ambient-intent mechanisms
		 * (mTLS) in `intent-explicit` dispatch mode.
		 */
		intentExplicit: true,

		extract: async (req: Request, ctx?: TokenBindingExtractContext) => {
			// Step 1 (spec §6): DPoP header presence.
			const header = req.get("dpop");
			if (header === undefined) {
				return null; // non-DPoP request — no binding
			}

			// Step 2 (spec §6): Only a single DPoP header value is permitted.
			if (header.includes(",")) {
				throw new DPoPError("multiple_headers", "Multiple DPoP header values presented");
			}

			// Steps 3–9 (spec §6): Structural validation + JWK screening + jkt.
			// `parseProof` is async (computes jkt via SubtleCrypto in proof.mts).
			// The flat DPoPProof shape from Sub-PR 2a: proof.jwk, proof.alg, proof.jkt.
			const proof = await parseProof(header);

			// Step 5 (spec §6): Algorithm allowlist check.
			// parseProof ensures alg is a non-empty string; whitelist check is here.
			if (!algWhitelist.includes(proof.alg)) {
				logger?.warn({ alg: proof.alg, whitelist: algWhitelist }, "dpop_alg_not_allowed");
				throw new DPoPError("alg_not_allowed", `alg ${proof.alg} is not in the allowlist`);
			}

			// Step 8 (spec §6): Signature verification.
			// Import the public key from proof.jwk (flat field from Sub-PR 2a).
			try {
				const publicKey = await importJWK(proof.jwk, proof.alg);
				await jwtVerify(header, publicKey, { typ: "dpop+jwt" });
			} catch (err) {
				// Re-throw DPoPError as-is (shouldn't happen here, but safe).
				if (err instanceof DPoPError) throw err;
				logger?.warn({ err }, "dpop_signature_invalid");
				throw new DPoPError("signature_invalid", "DPoP proof signature verification failed");
			}

			// Step 10 (spec §6): HTTP method match.
			if (proof.claims.htm.toUpperCase() !== req.method.toUpperCase()) {
				throw new DPoPError("htm_mismatch", "DPoP proof htm does not match request method", {
					expected: req.method.toUpperCase(),
					presented: proof.claims.htm,
				});
			}

			// Step 11 (spec §6): HTTP URI match — both sides normalized per §7.
			// `normalizeHtu` throws when either URL contains userinfo (the
			// reconstruction drops `username`/`password`, which would otherwise
			// let `https://attacker:pwn@as.example/...` equality-match the
			// server-built URL after canonicalization). Wrap so the contract
			// stays inside `DPoPError`.
			let expectedHtu: string;
			let presentedHtu: string;
			try {
				expectedHtu = normalizeHtu(buildRequestUrl(issuerOrigin, req));
				presentedHtu = normalizeHtu(proof.claims.htu);
			} catch (err) {
				throw new DPoPError(
					"malformed_proof",
					`DPoP htu canonicalization failed: ${(err as Error).message}`,
				);
			}
			if (expectedHtu !== presentedHtu) {
				throw new DPoPError("htu_mismatch", "DPoP proof htu does not match request URI", {
					expected: expectedHtu,
					presented: presentedHtu,
				});
			}

			// Step 12 (spec §6): iat acceptance window.
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

			// RFC 9449 §7.1: at a protected resource the proof MUST carry an
			// `ath` binding it to the access token it accompanies. Without it,
			// a proof captured alongside one request authorises any other
			// stolen token presented with it — the `htm`/`htu`/`iat` checks
			// above say nothing about *which* token the proof is for.
			//
			// Ordered BEFORE the replay check on purpose. A proof whose `ath`
			// does not match is not a legitimate use of its `jti`, so it must
			// not consume the replay slot: an attacker who intercepts a proof
			// could otherwise burn its `jti` by submitting it with a
			// mismatched token and have the client's own request rejected as
			// a replay. Checking the pair's coherence first keeps the replay
			// store recording only proofs that were actually honoured.
			//
			// `ctx` absent = the token-endpoint profile (§5), where no access
			// token exists yet. A stray `ath` there is ignored rather than
			// rejected: there is nothing for it to contradict, and failing the
			// grant over a pointless claim would break clients for no gain.
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

			// Step 13 (spec §6): JKT — already computed by parseProof (Sub-PR 2a).
			// Do NOT re-compute: proof.jkt is the canonical value.
			const { jkt } = proof;

			// Step 14 (spec §6): Replay check — atomic (jti, jkt) pair seen/mark.
			// Wrap so that transport faults (Redis ECONNREFUSED, etc.) surface
			// as the distinct `replay_store_unavailable` audit signal rather
			// than leaking a raw infrastructure error through `tokenBindingMw`
			// — operators triaging audit events need to distinguish "client
			// sent garbage" from "replay store is down" even when both map to
			// the same RFC 9449 §7 wire code `invalid_dpop_proof`.
			let alreadySeen: boolean;
			try {
				alreadySeen = await replayStore.seen(proof.claims.jti, jkt, replayTtlSeconds);
			} catch (err) {
				// Narrow the catch so only TRANSPORT / availability faults
				// surface as `replay_store_unavailable`. Programming-contract
				// violations propagate as-is:
				//   - DPoPError: a future refactor might shape replay-store
				//     errors directly as DPoPError; preserve that classification.
				//   - RangeError: `DPoPReplayStore.seen`'s interface JSDoc says
				//     implementations SHOULD throw `RangeError` on non-positive
				//     `ttlSeconds`. That is a programmer / config bug, NOT an
				//     availability fault — misclassifying it as
				//     `replay_store_unavailable` would mislead operator triage
				//     into checking Redis health when the actual fix is the
				//     ttl config.
				if (err instanceof DPoPError) throw err;
				if (err instanceof RangeError) throw err;
				logger?.error({ err, jti: proof.claims.jti }, "dpop_replay_store_unavailable");
				throw new DPoPError(
					"replay_store_unavailable",
					"DPoP replay store is unavailable; cannot determine replay status",
				);
			}
			if (alreadySeen) {
				throw new DPoPError(
					"replay_detected",
					"DPoP proof (jti, jkt) already seen in replay window",
					{
						jti: proof.claims.jti,
					},
				);
			}

			// Step 15 (spec §6): Return the sender-constrained token binding.
			// Confirmation shape is the RFC 7800 `cnf.jkt` variant only (Stage 1).
			// The `proof` object is NOT forwarded — sub-PR 2c reads only
			// `tokenBinding.confirmation.jkt` for cnf claim issuance.
			return {
				kind: "dpop",
				confirmation: { jkt },
			};
		},
	};
};
