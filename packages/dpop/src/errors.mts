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
	| "ath_mismatch";

/**
 * Thrown by `parseProof` and `verifyProof` for any DPoP validation failure.
 *
 * Wire-level `code` is hard-coded to `"invalid_dpop_proof"` (the only
 * RFC 9449 §7 token-endpoint code Phase 2 uses). The `reason` field carries
 * a granular sub-classification for audit emission — it must never reach
 * the wire.
 *
 * Per Wave 2 Phase 2 spec §5.6 + design principle §3.4.
 */
export class DPoPError extends Error {
	readonly code = "invalid_dpop_proof" as const;
	readonly reason: DPoPReasonCode;
	readonly detail?: Record<string, unknown>;

	constructor(reason: DPoPReasonCode, message: string, detail?: Record<string, unknown>) {
		super(message);
		this.name = "DPoPError";
		this.reason = reason;
		if (detail !== undefined) this.detail = detail;
	}
}

/**
 * The wire-level OAuth error code emitted by Phase 2 DPoP failures.
 * Always `"invalid_dpop_proof"` per RFC 9449 §7 — the only token-endpoint
 * error code Phase 2 uses. The alias is exported per spec §5.1 so consumers
 * can name the wire-side surface explicitly when constructing wire-level
 * error envelopes.
 */
export type DPoPErrorCode = DPoPError["code"];
