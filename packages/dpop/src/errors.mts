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
 * Granular internal reason code for a DPoP validation failure. For audit
 * emission only: it MUST NOT be forwarded to the client. The wire code is
 * {@link DPoPError.code}.
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
	| "replay_store_full"
	| "replay_store_fault"
	| "multiple_headers"
	| "ath_missing"
	| "ath_mismatch"
	| "nonce_required"
	| "nonce_invalid";

/**
 * Thrown by `parseProof` and `verifyProof` for any DPoP validation failure.
 * `code` goes on the wire; `reason` is for audit emission and must never
 * reach the wire.
 */
export class DPoPError extends Error {
	/**
	 * The wire-level code:
	 * - `use_dpop_nonce` (RFC 9449 §8 / §9) for `nonce_required` and
	 *   `nonce_invalid`: an instruction to retry with the nonce the answer
	 *   carries in `responseHeaders`, not a verdict on the proof.
	 * - `temporarily_unavailable` for `replay_store_unavailable`,
	 *   `replay_store_full` and `replay_store_fault`: the replay record could
	 *   not be read or written (the store is down, it is full — core's
	 *   in-process set holding DPoP's share of its cap — or it broke its own
	 *   contract), so the proof was not judged and core's dispatchers answer
	 *   503 (`unavailable`). The three reasons keep an outage, a flood or an
	 *   undersized cap, and a composition fault apart in the log.
	 * - `invalid_dpop_proof` (§7) for every other failure.
	 */
	readonly code: "invalid_dpop_proof" | "use_dpop_nonce" | "temporarily_unavailable";
	readonly reason: DPoPReasonCode;
	readonly detail?: Record<string, unknown>;
	/** Headers the HTTP answer must carry — `DPoP-Nonce` for the nonce refusals. */
	readonly responseHeaders?: Readonly<Record<string, string>>;
	/**
	 * Core's `TokenBindingRefusal.retryInstruction`: set for the nonce
	 * refusals, which are an instruction to retry rather than a verdict. The
	 * token-binding middlewares answer with it, and a protected resource
	 * challenges with this error's `code`, without knowing DPoP's codes.
	 */
	readonly retryInstruction?: string;
	/**
	 * Core's `TokenBindingRefusal.unavailable`: set for the three replay-store
	 * reasons, which are the server's fault. The token endpoint and a protected
	 * resource answer them `503 temporarily_unavailable` with this fixed
	 * description and no challenge — the proof may be perfectly good. What went
	 * wrong on the server is for the operator's log, not the client.
	 */
	readonly unavailable?: string;

	/**
	 * @param options.cause For the three replay-store reasons: the store's error
	 *   (core's `TokenBindingRefusal.cause`), logged as a projection by the
	 *   dispatcher that answers the 503, not by this package. For a
	 *   `malformed_proof` a library refused (jose's `JWKInvalid`, the `htu`
	 *   canonicalization): that library's error. `message` stays this package's
	 *   fixed text either way, so a library's words, which can quote what the
	 *   client sent, reach a logger only through a projection of the cause.
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
		const outage =
			reason === "replay_store_unavailable" ||
			reason === "replay_store_full" ||
			reason === "replay_store_fault";
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
 * The wire-level OAuth error code of a {@link DPoPError}, exported so
 * consumers can name it when building wire-level error envelopes.
 */
export type DPoPErrorCode = DPoPError["code"];
