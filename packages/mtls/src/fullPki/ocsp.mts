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
 * OCSP (RFC 6960) status lookup for `mode = "full-pki"`: `createOcspResolver` asks the responders
 * a certificate names, in turn, through the cache in `ocspCache.mts`, and judges each answer in
 * the order `query` sets out: the request (`ocspRequest.mts`), the fetch (`ocspFetch.mts`), the
 * parse (`ocspParse.mts`), the shape (`ocspShape.mts`), the signer (`ocspSigner.mts`), a
 * delegated responder's own status (`ocspDelegate.mts`), the nonce, and the status and its
 * freshness (`ocspStatus.mts`). `pkijs` only encodes the request and decodes the response.
 *
 * Always a responder fetch: Node exposes no stapled response for a client
 * certificate, so a certificate demanding must-staple (RFC 7633) is refused
 * by `checkMustStaple`.
 *
 * The answer is verified by these stages, not by pkijs: `BasicOCSPResponse.verify`
 * ignores `id-kp-OCSPSigning` (any certificate the CA issued could vouch for
 * itself), and `getCertificateStatus` answers `unknown` for a response about
 * another certificate. Per RFC 6960 §4.2.2.2 a response is believed only when
 * signed by the issuing CA, or by a certificate that CA issued which carries
 * `id-kp-OCSPSigning`, is within its validity, has no unprocessed critical
 * extension, and meets the path's algorithm policy. A delegated responder
 * without `id-pkix-ocsp-nocheck` (§4.2.2.2.1) is itself checked through
 * `responderRevocation` (the CRL arm under `mode = "both"`) on every use,
 * cache hits included; with no source to check it, the answer is taken and
 * flagged `responderUnchecked` — the local-policy deviation the README states.
 *
 * - Shape checks run before the signature, can only refuse, and so are
 *   remembered (`ocspShape.mts`).
 * - Every request carries a 16-byte nonce (§4.4.1, RFC 8954). A different
 *   echo is refused; a missing one too unless `requireNonce: false` (a
 *   pre-producing responder), since otherwise a "good" captured before a
 *   revocation replays until its `nextUpdate`.
 * - `unknown` (§2.2) is unavailable, not good: a responder that lost its
 *   database must not un-revoke everything.
 */

import * as pkijs from "pkijs";
import type { AlgorithmPolicy } from "./algorithms.mjs";
import { DEFAULT_ALGORITHM_POLICY } from "./defaults.mjs";
import type { GuardedFetch } from "./fetchGuard.mjs";
import type { Answer, OcspLookup, OcspResponderUnavailable } from "./ocspAnswer.mjs";
import {
	createOcspCache,
	DEFAULT_MAX_CACHE_ENTRIES,
	issuerKeyId,
	serialHex,
} from "./ocspCache.mjs";
import {
	checkDelegateRevocation,
	hasNoCheck,
	type ResponderRevocationCheck,
	type ResponderVerdict,
} from "./ocspDelegate.mjs";
import { fetchResponse } from "./ocspFetch.mjs";
import { parseResponse } from "./ocspParse.mjs";
import { buildRequest, checkNonce } from "./ocspRequest.mjs";
import { ocspResponders } from "./ocspResponders.mjs";
import { checkResponseShape } from "./ocspShape.mjs";
import { identifySigner, verifySignature } from "./ocspSigner.mjs";
import { decodeStatus, freshness } from "./ocspStatus.mjs";

export type {
	OcspCertificateStatus,
	OcspLookup,
	OcspResponderUnavailable,
	OcspUnavailableReason,
} from "./ocspAnswer.mjs";
export { OCSP_NEGATIVE_CACHE_TTL_MS } from "./ocspCache.mjs";
export type { ResponderRevocationCheck, ResponderRevocationOutcome } from "./ocspDelegate.mjs";
export { checkMustStaple } from "./ocspMustStaple.mjs";
export { type OcspResponders, ocspResponders } from "./ocspResponders.mjs";
export { OCSP_CLOCK_SKEW_MS, OCSP_UNDATED_RESPONSE_MAX_AGE_MS } from "./ocspStatus.mjs";

export interface OcspResolverOptions {
	readonly fetch: GuardedFetch;
	/**
	 * Upper bound on how long an answer is reused, in seconds. The response's
	 * own `nextUpdate` still wins when it is sooner.
	 */
	readonly cacheTtlSeconds: number;
	/**
	 * The signature-algorithm and key-size policy the validated path is held
	 * to, applied to the response's signature and to a delegated responder's
	 * certificate too. Defaults to `DEFAULT_ALGORITHM_POLICY`, the strict
	 * policy, so omitting it can only make the check stricter; `validate.mts`
	 * passes the configured policy.
	 */
	readonly algorithms?: AlgorithmPolicy;
	/**
	 * Refuse a response that does not carry the request's nonce. Defaults to
	 * `true`; see the module header for what `false` gives up.
	 */
	readonly requireNonce?: boolean;
	/** Bound on cache size. Entries are per certificate, so the default is roomier than the CRL cache's. */
	readonly maxCacheEntries?: number;
	/**
	 * How a delegated responder's own certificate is checked for revocation
	 * when it lacks `id-pkix-ocsp-nocheck` (RFC 6960 §4.2.2.2.1); `validate.mts`
	 * wires the CRL arm under `mode = "both"`. Absent, or answering
	 * `unspecified`, such a responder's answer is taken and flagged
	 * `responderUnchecked`.
	 */
	readonly responderRevocation?: ResponderRevocationCheck;
}

export interface OcspResolver {
	/**
	 * Ask the responders `certificate` names about it, verifying each answer
	 * against `issuer`, the certificate that issued it — the next element up
	 * the validated path. Only an answer whose signer is that issuer, or a
	 * responder that issuer delegated to, is ever returned or cached.
	 */
	resolve(
		certificate: pkijs.Certificate,
		issuer: pkijs.Certificate,
		now: Date,
	): Promise<OcspLookup>;
	/** Entry count, usable and remembered-unavailable alike — for tests and for a future metric. */
	size(): number;
}

export const createOcspResolver = (options: OcspResolverOptions): OcspResolver => {
	const maxEntries = options.maxCacheEntries ?? DEFAULT_MAX_CACHE_ENTRIES;
	const requireNonce = options.requireNonce ?? true;
	const algorithms = options.algorithms ?? DEFAULT_ALGORITHM_POLICY;

	/** Ask `url` about `certificate` and judge the answer. Everything the nonce binds happens here. */
	const query = async (
		url: string,
		certificate: pkijs.Certificate,
		issuer: pkijs.Certificate,
		now: Date,
	): Promise<Answer> => {
		const crypto = pkijs.getCrypto(true);
		const request = await buildRequest(certificate, issuer, crypto);
		const fetched = await fetchResponse(options, url, request.der);
		if (!fetched.ok) return fetched;

		const parsed = parseResponse(fetched.bytes);
		if (!parsed.ok) return parsed;
		const basic = parsed.basic;

		// Shape before signature, as in `crl.mts`: nothing an unverified
		// response *says* is acted on here, only what it is shaped like, and
		// the answer is at most "do not use it".
		const shape = await checkResponseShape(
			basic,
			certificate,
			issuer,
			request.certId,
			crypto,
			algorithms,
		);
		if (!shape.ok) return shape;
		const single = shape.single;

		const signer = await identifySigner(basic, issuer, now, crypto, algorithms);
		if (!signer.ok) return { ok: false, reason: signer.reason, detail: signer.detail };
		const signature = await verifySignature(basic, signer.signer, crypto);
		if (!signature.ok) {
			return {
				ok: false,
				reason: "bad_signature",
				detail: signature.detail,
				...(signature.cause !== undefined ? { cause: signature.cause } : {}),
			};
		}
		// The delegated responder's own certificate, checked here and again
		// whenever this answer is served from the cache.
		const delegate =
			signer.delegate !== undefined && !hasNoCheck(signer.delegate) ? signer.delegate : undefined;
		let responderUnchecked = false;
		if (delegate !== undefined) {
			const verdict = await checkResponder(delegate, issuer, now);
			if (!verdict.ok) return verdict;
			responderUnchecked = verdict.unchecked;
		}

		// The nonce is judged on bytes the responder actually signed.
		const nonce = checkNonce(basic, request.nonce, requireNonce);
		if (!nonce.ok) return nonce;

		const decoded = decodeStatus(single.certStatus);
		if (!decoded.ok) return { ok: false, reason: "unparseable", detail: decoded.detail };

		const fresh = freshness(single, now, options.cacheTtlSeconds);
		if (!fresh.ok) return fresh;

		if (decoded.status === "unknown") {
			return {
				ok: false,
				reason: "unknown",
				detail: `the responder at ${url} does not know the certificate (RFC 6960 §2.2)`,
			};
		}
		return {
			ok: true,
			responderUnchecked,
			status: decoded.status,
			expiresAt: fresh.expiresAt,
			...(delegate === undefined ? {} : { delegate }),
		};
	};

	/** The delegated responder's own certificate, through the source the caller wired. */
	const checkResponder = (
		delegate: pkijs.Certificate,
		issuer: pkijs.Certificate,
		now: Date,
	): Promise<ResponderVerdict> => checkDelegateRevocation(options, delegate, issuer, now);

	const cache = createOcspCache(maxEntries, query, checkResponder);

	return {
		size: () => cache.size(),

		resolve: async (certificate, issuer, now) => {
			const responders = ocspResponders(certificate);
			if (!responders.ok) return responders;

			const issuerId = issuerKeyId(issuer);
			const serial = serialHex(certificate);
			const failures: OcspResponderUnavailable[] = [];
			for (const url of responders.urls) {
				const answer = await cache.lookup(url, certificate, issuer, issuerId, serial, now);
				if (answer.ok) {
					return {
						ok: true,
						responder: url,
						status: answer.status,
						...(answer.responderUnchecked ? { responderUnchecked: true } : {}),
					};
				}
				failures.push({
					url,
					reason: answer.reason,
					detail: answer.detail,
					...(answer.cause !== undefined ? { cause: answer.cause } : {}),
					...(answer.outage ? { outage: true } : {}),
				});
			}
			const last = failures[failures.length - 1];
			return {
				ok: false,
				reason: last?.reason ?? "fetch_failed",
				detail: failures
					.map((entry) => `${entry.url}: ${entry.reason} (${entry.detail})`)
					.join("; "),
				...(last?.cause !== undefined ? { cause: last.cause } : {}),
				...(failures.length > 0 && failures.every((entry) => entry.outage) ? { outage: true } : {}),
				responders: failures,
			};
		},
	};
};
