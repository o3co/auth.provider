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
 * The wire-level error code is `"invalid_certificate"` for every reason but
 * `revocation_unavailable`, which is `"temporarily_unavailable"` (see
 * {@link MtlsError}). This reason field is for internal audit emission only —
 * it MUST NOT be forwarded to the client verbatim (the wire
 * `error_description` may contain a safe, user-facing variant).
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
	| "untrusted_proxy"
	/**
	 * `full-pki` under `on-unavailable = "reject"` could not determine a
	 * certificate's revocation status because a CRL distribution point or an
	 * OCSP responder did not answer usefully — unreachable, timed out, an HTTP
	 * error, an answer that is not DER, a stale list. The server's outage, not
	 * a verdict on the certificate: core's dispatcher answers it `503` and logs
	 * it once, at error.
	 */
	| "revocation_unavailable";

/**
 * Thrown by the mTLS cert extraction and validation pipeline for any
 * certificate validation failure — core's `TokenBindingRefusal`.
 *
 * Wire-level `code` is `"invalid_certificate"` for a verdict on the
 * certificate. For `revocation_unavailable` — the server could not reach a
 * verdict — it is `"temporarily_unavailable"`, with `unavailable` set: core's
 * dispatchers answer that `503` with no challenge, and log it once at error
 * (`token_binding_unavailable`, `protected_resource_binding_unavailable`).
 * The `reason` field carries a granular sub-classification for audit
 * emission; it must never reach the wire verbatim (use a safe error
 * description instead).
 *
 * The message is this package's own fixed text. When a parser refused the
 * material, its error is the standard `cause` — never copied into the
 * message, since a parser's message is its reading of what the client sent.
 * An outage's `cause` is an {@link MtlsRevocationUnavailableError}.
 *
 * Per Wave 2 Phase 3 spec §5.5 + design principle §3.4.
 */
export class MtlsError extends Error {
	readonly code: "invalid_certificate" | "temporarily_unavailable";
	readonly reason: MtlsReasonCode;
	readonly detail?: Record<string, unknown>;
	/** Core's `TokenBindingRefusal.unavailable`: set for `revocation_unavailable` alone. */
	readonly unavailable?: string;

	constructor(
		reason: MtlsReasonCode,
		message: string,
		detail?: Record<string, unknown>,
		options?: ErrorOptions,
	) {
		super(message, options);
		this.name = "MtlsError";
		this.reason = reason;
		if (reason === "revocation_unavailable") {
			this.code = "temporarily_unavailable";
			this.unavailable =
				"the client certificate's revocation status could not be determined; retry later";
		} else {
			this.code = "invalid_certificate";
		}
		if (detail !== undefined) this.detail = detail;
	}
}

/**
 * The cause of a `revocation_unavailable` refusal: this package's account of
 * which revocation source could not answer and why — subjects, URLs,
 * reasons, statuses and transport codes, in its own words — with the
 * library's error, when one threw, as its own `cause`. The dispatcher's
 * outage line carries its projection.
 */
export class MtlsRevocationUnavailableError extends Error {
	constructor(detail: string, options?: ErrorOptions) {
		super(detail, options);
		this.name = "MtlsRevocationUnavailableError";
	}
}

/**
 * The wire-level OAuth error codes emitted by Phase 3 mTLS failures:
 * `"invalid_certificate"` for a verdict on the certificate, and
 * `"temporarily_unavailable"` for a revocation source that could not answer
 * — exported per spec §5.1 so consumers can name the wire-side surface
 * explicitly when constructing error envelopes without importing the class.
 */
export type MtlsErrorCode = MtlsError["code"];
