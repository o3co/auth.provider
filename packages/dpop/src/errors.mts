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
 * Granular internal reason code for a DPoP validation failure.
 *
 * The wire-level error code is `"invalid_dpop_proof"` (RFC 9449 §7) for a
 * proof found invalid; see {@link DPoPError.code} for the two that are not a
 * verdict on the proof. This reason field is for internal audit emission
 * only — it MUST NOT be forwarded to the client.
 *
 * Per Wave 2 Phase 2 spec §5.6.
 */
export type DPoPReasonCode =
	| "malformed_proof"
	| "typ_mismatch"
	| "alg_not_allowed"
	| "missing_jwk"
	| "private_jwk"
	| "signature_invalid"
	| "missing_claim"
	| "htm_mismatch"
	| "htu_mismatch"
	| "iat_out_of_window"
	| "replay_detected"
	| "replay_store_unavailable"
	| "replay_store_fault"
	| "multiple_headers"
	| "ath_missing"
	| "ath_mismatch"
	| "nonce_required"
	| "nonce_invalid";

/**
 * Thrown by `parseProof` and `verifyProof` for any DPoP validation failure.
 *
 * Wire-level `code` is `"invalid_dpop_proof"` (RFC 9449 §7) for every
 * failure but four. The nonce ones are `"use_dpop_nonce"` (§8 / §9, #530):
 * `nonce_required` and `nonce_invalid` are an instruction to retry with the
 * nonce the answer carries in `responseHeaders`, not a verdict on the
 * proof. `replay_store_unavailable` and `replay_store_fault` are
 * `"temporarily_unavailable"`: the replay record could not be read or
 * written — the store is down, or it broke its own contract — so the proof
 * was not judged at all, and core's dispatchers answer it 503
 * (`unavailable`). The two reasons keep an outage and a composition fault
 * apart in the audit record. The `reason`
 * field carries a granular sub-classification for audit emission — it must
 * never reach the wire.
 *
 * Per Wave 2 Phase 2 spec §5.6 + design principle §3.4.
 */
export class DPoPError extends Error {
	/**
	 * The wire-level code: `invalid_dpop_proof` (RFC 9449 §7) for every
	 * failure but one. A proof that lacks the server-provided nonce, or
	 * carries a stale one, is `use_dpop_nonce` (§8 / §9, #530) — the one
	 * refusal that is an instruction rather than a verdict, and the answer
	 * that carries it also carries the nonce to retry with, in
	 * `responseHeaders`. A replay store that cannot be read, or answers with
	 * its own contract error, is `temporarily_unavailable`: the server's
	 * fault, not a verdict (`unavailable`).
	 */
	readonly code: "invalid_dpop_proof" | "use_dpop_nonce" | "temporarily_unavailable";
	readonly reason: DPoPReasonCode;
	readonly detail?: Record<string, unknown>;
	/** Headers the HTTP answer must carry — `DPoP-Nonce` for the nonce refusals (#530). */
	readonly responseHeaders?: Readonly<Record<string, string>>;
	/**
	 * Core's `TokenBindingRefusal.retryInstruction`: set for the nonce
	 * refusals, which are an instruction to retry rather than a verdict. The
	 * token-binding middlewares answer with it, and a protected resource
	 * challenges with this error's `code`, without knowing DPoP's codes.
	 */
	readonly retryInstruction?: string;
	/**
	 * Core's `TokenBindingRefusal.unavailable`: set for
	 * `replay_store_unavailable` and `replay_store_fault`, the refusals that
	 * are the server's fault. The token endpoint and a protected resource
	 * answer them `503 temporarily_unavailable` with this description and no
	 * challenge — the proof may be perfectly good. The description is the same
	 * for both: what went wrong on the server is the operator's to read in the
	 * log, not the client's.
	 */
	readonly unavailable?: string;

	/**
	 * @param options.cause For the two outage reasons: the replay store's error
	 *   that stopped the verdict — core's `TokenBindingRefusal.cause`. The
	 *   dispatcher that answers the 503 logs its projection; this package does
	 *   not log the outage itself. For a `malformed_proof` a library refused
	 *   (jose's `JWKInvalid`, the `htu` canonicalization): that library's error.
	 *   `message` stays this package's own fixed text either way, so a library's
	 *   words — which can quote what the client sent — are never flattened into
	 *   it; a logger reaches them only through a projection of the cause.
	 */
	constructor(
		reason: DPoPReasonCode,
		message: string,
		detail?: Record<string, unknown>,
		responseHeaders?: Readonly<Record<string, string>>,
		options?: ErrorOptions,
	) {
		super(message, options);
		this.name = "DPoPError";
		this.reason = reason;
		const nonceRefusal = reason === "nonce_required" || reason === "nonce_invalid";
		const outage = reason === "replay_store_unavailable" || reason === "replay_store_fault";
		this.code = nonceRefusal
			? "use_dpop_nonce"
			: outage
				? "temporarily_unavailable"
				: "invalid_dpop_proof";
		if (nonceRefusal) {
			this.retryInstruction =
				"a server-provided nonce is required; retry with the value of the DPoP-Nonce header";
		}
		if (outage) {
			this.unavailable =
				"DPoP proofs cannot be checked for replay right now; retry the request later";
		}
		if (detail !== undefined) this.detail = detail;
		if (responseHeaders !== undefined) this.responseHeaders = responseHeaders;
	}
}

/**
 * The wire-level OAuth error code emitted by DPoP failures:
 * `"invalid_dpop_proof"` (RFC 9449 §7), `"use_dpop_nonce"` (§8 / §9, #530)
 * for a proof that lacks the server-provided nonce or carries a stale one,
 * or `"temporarily_unavailable"` when the replay store cannot be read. The
 * alias is exported per spec §5.1 so consumers can name the
 * wire-side surface explicitly when constructing wire-level error
 * envelopes.
 */
export type DPoPErrorCode = DPoPError["code"];
