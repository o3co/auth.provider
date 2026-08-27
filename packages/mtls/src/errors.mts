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
 * Granular internal reason code for an mTLS certificate validation failure.
 *
 * The wire-level error code is always `"invalid_certificate"` (see §3.4).
 * This reason field is for internal audit emission only — it MUST NOT be
 * forwarded to the client verbatim (the wire `error_description` may contain
 * a safe, user-facing variant).
 *
 * Per Wave 2 Phase 3 spec §5.5 + §3.4.
 */
export type MtlsReasonCode =
	| "malformed_header"
	| "unknown_dialect"
	| "cert_decode_failed"
	| "cert_expired"
	| "cert_not_yet_valid"
	| "chain_validation_failed"
	| "trusted_cas_unconfigured"
	| "tls_peer_unavailable"
	/**
	 * A forwarded-certificate header arrived on a connection whose peer is not
	 * in `oauth.mtls.trusted-proxies` (issue #280). Either an attacker is
	 * asserting a client identity by setting the header directly, or the
	 * deployment's proxy address is missing from the allowlist — the audit
	 * record carries the observed peer address so the two are separable.
	 */
	| "untrusted_proxy";

/**
 * Thrown by the mTLS cert extraction and validation pipeline for any
 * certificate validation failure.
 *
 * Wire-level `code` is hard-coded to `"invalid_certificate"` — the single
 * stable error code Phase 3 emits. The `reason` field carries a granular
 * sub-classification for audit emission; it must never reach the wire
 * verbatim (use a safe error description instead).
 *
 * Per Wave 2 Phase 3 spec §5.5 + design principle §3.4.
 */
export class MtlsError extends Error {
	readonly code = "invalid_certificate" as const;
	readonly reason: MtlsReasonCode;
	readonly detail?: Record<string, unknown>;

	constructor(reason: MtlsReasonCode, message: string, detail?: Record<string, unknown>) {
		super(message);
		this.name = "MtlsError";
		this.reason = reason;
		if (detail !== undefined) this.detail = detail;
	}
}

/**
 * The wire-level OAuth error code emitted by Phase 3 mTLS failures.
 * Always `"invalid_certificate"` — the stable audit + wire surface exported
 * per spec §5.1 so consumers can name the wire-side surface explicitly when
 * constructing error envelopes without importing the class.
 */
export type MtlsErrorCode = MtlsError["code"];
