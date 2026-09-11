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
 * The wire-level error code is always `"invalid_dpop_proof"` (RFC 9449 §7).
 * This reason field is for internal audit emission only — it MUST NOT be
 * forwarded to the client.
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
	| "multiple_headers"
	| "ath_missing"
	| "ath_mismatch"
	| "nonce_required"
	| "nonce_invalid";

/**
 * Thrown by `parseProof` and `verifyProof` for any DPoP validation failure.
 *
 * Wire-level `code` is `"invalid_dpop_proof"` (RFC 9449 §7) for every
 * failure but the nonce ones, which are `"use_dpop_nonce"` (§8 / §9, #530):
 * `nonce_required` and `nonce_invalid` are an instruction to retry with the
 * nonce the answer carries in `responseHeaders`, not a verdict on the
 * proof. The `reason` field carries a granular sub-classification for
 * audit emission — it must never reach the wire.
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
	 * `responseHeaders`.
	 */
	readonly code: "invalid_dpop_proof" | "use_dpop_nonce";
	readonly reason: DPoPReasonCode;
	readonly detail?: Record<string, unknown>;
	/** Headers the HTTP answer must carry — `DPoP-Nonce` for the nonce refusals (#530). */
	readonly responseHeaders?: Readonly<Record<string, string>>;

	constructor(
		reason: DPoPReasonCode,
		message: string,
		detail?: Record<string, unknown>,
		responseHeaders?: Readonly<Record<string, string>>,
	) {
		super(message);
		this.name = "DPoPError";
		this.reason = reason;
		this.code =
			reason === "nonce_required" || reason === "nonce_invalid"
				? "use_dpop_nonce"
				: "invalid_dpop_proof";
		if (detail !== undefined) this.detail = detail;
		if (responseHeaders !== undefined) this.responseHeaders = responseHeaders;
	}
}

/**
 * The wire-level OAuth error code emitted by DPoP failures:
 * `"invalid_dpop_proof"` (RFC 9449 §7), or `"use_dpop_nonce"` (§8 / §9,
 * #530) for a proof that lacks the server-provided nonce or carries a
 * stale one. The alias is exported per spec §5.1 so consumers can name the
 * wire-side surface explicitly when constructing wire-level error
 * envelopes.
 */
export type DPoPErrorCode = DPoPError["code"];
