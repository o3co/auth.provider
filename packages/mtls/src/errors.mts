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

import { lineSafeText } from "@o3co/auth-provider-core";

/**
 * Granular internal reason code for an mTLS certificate validation failure,
 * for audit emission only: it MUST NOT be forwarded to the client verbatim
 * (the wire `error_description` may carry a safe variant). The wire code is
 * on {@link MtlsError}.
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
	 * A forwarded-certificate header arrived from a peer not in
	 * `mtls.trustedProxies`: either an attacker setting the header
	 * directly or a proxy missing from the allowlist. The audit record carries
	 * the observed peer address so the two are separable.
	 */
	| "untrusted_proxy"
	/**
	 * `full-pki` under `on-unavailable = "reject"` could not determine a
	 * revocation status because a CRL distribution point or OCSP responder did
	 * not answer usefully (unreachable, timed out, HTTP error, not DER, stale).
	 * The server's outage, not a verdict: core answers it `503` and logs it
	 * once, at error.
	 */
	| "revocation_unavailable";

/**
 * Thrown by the mTLS extraction and validation pipeline for any certificate
 * validation failure — core's `TokenBindingRefusal`.
 *
 * `code` is `"invalid_certificate"` for a verdict on the certificate. For
 * `revocation_unavailable` (no verdict reachable) it is
 * `"temporarily_unavailable"` with `unavailable` set: core answers that `503`
 * with no challenge and logs it once at error. `reason` is for audit only and
 * never reaches the wire verbatim.
 *
 * The message is this package's own fixed text. A parser's error goes in
 * `cause`, never into the message, since it is the parser's reading of what
 * the client sent. An outage's `cause` is an
 * {@link MtlsRevocationUnavailableError}.
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
 * One revocation source (CRL distribution point or OCSP responder) that could
 * not be used, as a member of an {@link MtlsRevocationUnavailableError}:
 * `<source> <url>: <reason> — <detail>; for <subject>`, with the library's
 * error, when one threw, as `cause`. One error per source, so core's
 * `loggableError` cap (256 characters) cuts no other source's account; the
 * subject comes last so the cap cuts it, never the URL or the reason. URL,
 * detail and subject are foreign text, so each is on one line and capped
 * (`lineSafeText`) in the message and the fields alike.
 */
export class MtlsRevocationSourceError extends Error {
	readonly source: "crl" | "ocsp";
	readonly url?: string;
	/** The source's reason code (`fetch_failed`, `unparseable`, `stale`, …), which a projection keeps. */
	readonly reason: string;
	/** The subject of the certificate this source was asked about, on one line (`O=Example Corp, CN=client`). */
	readonly subject: string;

	constructor(
		failure: {
			readonly source: "crl" | "ocsp";
			readonly url?: string;
			readonly reason: string;
			readonly detail: string;
			readonly subject: string;
		},
		options?: ErrorOptions,
	) {
		const url = lineSafeText(failure.url);
		const subject = lineSafeText(failure.subject);
		super(
			`${failure.source}${url !== undefined ? ` ${url}` : ""}: ${failure.reason} — ${lineSafeText(failure.detail)}; for ${subject}`,
			options,
		);
		this.name = "MtlsRevocationSourceError";
		this.source = failure.source;
		if (url !== undefined) this.url = url;
		this.reason = failure.reason;
		this.subject = subject;
	}
}

/**
 * The cause of a `revocation_unavailable` refusal. Its members are the
 * {@link MtlsRevocationSourceError}s, one per unusable source for every
 * certificate on the path, leaf first and OCSP before CRL per certificate;
 * its message names each certificate whose status could not be determined.
 * Under `revocation.mode = "both"`, a failed responder is a member even when
 * the CRL then decided that certificate: it is part of the same outage.
 */
export class MtlsRevocationUnavailableError extends AggregateError {
	/** The subjects of the certificates whose status could not be determined, leaf first, each on one line. */
	readonly subjects: readonly string[];

	constructor(subjects: readonly string[], sources: readonly MtlsRevocationSourceError[]) {
		super(sources, `revocation status could not be determined for ${subjects.join("; ")}`);
		this.name = "MtlsRevocationUnavailableError";
		this.subjects = subjects;
	}
}

/**
 * The wire-level OAuth error codes of mTLS failures, so consumers can name
 * them in error envelopes without importing the class.
 */
export type MtlsErrorCode = MtlsError["code"];
