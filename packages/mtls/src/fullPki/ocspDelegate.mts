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
 * A delegated responder's own revocation status (RFC 6960 §4.2.2.2.1): exempt only when its
 * certificate carries `id-pkix-ocsp-nocheck` as a DER `NULL`, otherwise checked through the
 * caller's source, and taken as `responderUnchecked` when there is none.
 */

import type * as pkijs from "pkijs";
import type { OcspUnavailableReason } from "./ocspAnswer.mjs";

/** `id-pkix-ocsp-nocheck` (RFC 6960 §4.2.2.2.1): the CA vouches for the responder for its certificate's lifetime. */
const OID_OCSP_NOCHECK = "1.3.6.1.5.5.7.48.1.5";

/** What {@link ResponderRevocationCheck} learned about a delegated responder's certificate. */
export type ResponderRevocationOutcome =
	| { readonly kind: "determined" }
	/** The CA named no source for the responder's certificate (§4.2.2.2.1, third option): local policy decides, which is to take the answer and report `responderUnchecked`. */
	| { readonly kind: "unspecified" }
	| { readonly kind: "revoked"; readonly detail: string }
	| {
			readonly kind: "unavailable";
			readonly reason: string;
			readonly detail: string;
			readonly cause?: unknown;
			/** The source for the responder's status did not answer usefully. */
			readonly outage?: true;
	  };

export type ResponderRevocationCheck = (
	responder: pkijs.Certificate,
	issuer: pkijs.Certificate,
	now: Date,
) => Promise<ResponderRevocationOutcome>;

/**
 * Whether a delegated responder's certificate carries `id-pkix-ocsp-nocheck`
 * with the DER `NULL` value RFC 6960 §4.2.2.2.1 specifies. Any other value
 * buys no exemption: it is not a statement the CA wrote.
 */
export const hasNoCheck = (certificate: pkijs.Certificate): boolean => {
	const extension = certificate.extensions?.find((ext) => ext.extnID === OID_OCSP_NOCHECK);
	if (extension === undefined) return false;
	const bytes = extension.extnValue.valueBlock.valueHexView;
	return bytes.length === 2 && bytes[0] === 0x05 && bytes[1] === 0x00;
};

/** What a delegated responder's own status allows: its answer, flagged when unchecked, or a refusal. */
export type ResponderVerdict =
	| { ok: true; unchecked: boolean }
	| {
			ok: false;
			reason: OcspUnavailableReason;
			detail: string;
			cause?: unknown;
			outage?: true;
	  };

/**
 * A delegated responder's own certificate. RFC 6960 §4.2.2.2.1 lets a
 * client skip this only for a responder carrying `id-pkix-ocsp-nocheck`;
 * otherwise it is checked through the source the caller wired — the CA's
 * CRL, which the responder cannot answer for itself. A revoked responder's
 * `good` is worth nothing. With no source wired, or none the CA named, the
 * answer is taken and the deviation reported. Called when the answer is
 * built and on every cache hit, since the cached status outlives the check.
 */
export const checkDelegateRevocation = async (
	options: { readonly responderRevocation?: ResponderRevocationCheck },
	delegate: pkijs.Certificate,
	issuer: pkijs.Certificate,
	now: Date,
): Promise<ResponderVerdict> => {
	if (options.responderRevocation === undefined) return { ok: true, unchecked: true };
	const own = await options.responderRevocation(delegate, issuer, now);
	if (own.kind === "revoked") {
		return {
			ok: false,
			reason: "responder_revoked",
			detail: `the delegated responder's certificate is revoked: ${own.detail}`,
		};
	}
	if (own.kind === "unavailable") {
		return {
			ok: false,
			reason: "responder_status_unavailable",
			detail:
				"the delegated responder's own revocation status is unavailable " +
				`(${own.reason}): ${own.detail}`,
			...(own.cause !== undefined ? { cause: own.cause } : {}),
			...(own.outage ? { outage: true } : {}),
		};
	}
	return { ok: true, unchecked: own.kind === "unspecified" };
};
