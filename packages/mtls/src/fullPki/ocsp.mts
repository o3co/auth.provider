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
 * OCSP (RFC 6960) status lookup, verification and caching for
 * `mode = "full-pki"`. `pkijs` only encodes the request and decodes the
 * response; asking the responder (a POST under `fetchGuard.mts`), verifying
 * who signed the answer, matching the nonce, judging freshness and caching
 * happen here.
 *
 * Always a responder fetch: Node exposes no stapled response for a client
 * certificate, so a certificate demanding must-staple (RFC 7633) is refused
 * by `checkMustStaple`.
 *
 * The answer is verified here, not by pkijs: `BasicOCSPResponse.verify`
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
 * - As in `crl.mts`, shape checks (the matching `CertID`, critical
 *   extensions, the response's signature algorithm — pkijs accepts SHA-1)
 *   run before the signature, can only refuse, and so are remembered.
 * - The `CertID` hash is SHA-1 (§4.1.1): a lookup key, not a signature, and
 *   the one responders reliably answer. Another hash in a response is matched
 *   by recomputing.
 * - Every request carries a 16-byte nonce (§4.4.1, RFC 8954). A different
 *   echo is refused; a missing one too unless `requireNonce: false` (a
 *   pre-producing responder), since otherwise a "good" captured before a
 *   revocation replays until its `nextUpdate`.
 * - `unknown` (§2.2) is unavailable, not good: a responder that lost its
 *   database must not un-revoke everything.
 * - Caching is keyed per certificate: concurrent lookups share a request;
 *   answers live until `nextUpdate` or `cache-ttl-seconds`; failures are
 *   remembered for `OCSP_NEGATIVE_CACHE_TTL_MS` per responder (transport or
 *   responder-level) or per certificate (an unusable answer); `bad_signature`
 *   and `nonce_mismatch` are never remembered.
 * - Unavailabilities carry `reason`, `detail` and `cause` as in `crl.mts`,
 *   and are an `outage` when the responder did not answer usefully
 *   (`isSourceFailure`, `unparseable`, `responder_error`, `stale`, or a
 *   delegated responder's status unreadable for such a reason).
 */

import { createHash } from "node:crypto";
import * as pkijs from "pkijs";
import type { AlgorithmPolicy } from "./algorithms.mjs";
import { CRL_NEGATIVE_CACHE_TTL_MS } from "./crl.mjs";
import { DEFAULT_ALGORITHM_POLICY } from "./defaults.mjs";
import type { GuardedFetch } from "./fetchGuard.mjs";
import {
	type Answer,
	markOutage,
	type OcspCertificateStatus,
	type OcspLookup,
	type OcspResponderUnavailable,
} from "./ocspAnswer.mjs";
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
export type { ResponderRevocationCheck, ResponderRevocationOutcome } from "./ocspDelegate.mjs";
export { checkMustStaple } from "./ocspMustStaple.mjs";
export { type OcspResponders, ocspResponders } from "./ocspResponders.mjs";
export { OCSP_CLOCK_SKEW_MS, OCSP_UNDATED_RESPONSE_MAX_AGE_MS } from "./ocspStatus.mjs";

/**
 * How long a responder that could not be used is remembered, in
 * milliseconds. The CRL resolver's window, for the CRL resolver's reasons.
 */
export const OCSP_NEGATIVE_CACHE_TTL_MS = CRL_NEGATIVE_CACHE_TTL_MS;

/** Reasons remembered for the negative window, and at which granularity. */
type RespondersFailure =
	| "fetch_failed"
	| "unparseable"
	| "responder_error"
	| "responder_revoked"
	| "responder_status_unavailable";
type CertificateFailure =
	| "no_matching_response"
	| "unsupported_critical_extension"
	| "algorithm_not_permitted"
	| "nonce_missing"
	| "not_yet_valid"
	| "stale"
	| "unknown";

const RESPONDER_FAILURES: ReadonlySet<string> = new Set<RespondersFailure>([
	"fetch_failed",
	"unparseable",
	"responder_error",
	"responder_revoked",
	"responder_status_unavailable",
]);
const CERTIFICATE_FAILURES: ReadonlySet<string> = new Set<CertificateFailure>([
	"no_matching_response",
	"unsupported_critical_extension",
	"algorithm_not_permitted",
	"nonce_missing",
	"not_yet_valid",
	"stale",
	"unknown",
]);

type CacheEntry =
	| {
			readonly kind: "status";
			readonly status: OcspCertificateStatus;
			/** Epoch millis after which the responder must be asked again. */
			readonly expiresAt: number;
			/** The delegated responder to re-check before this entry is believed. */
			readonly delegate?: pkijs.Certificate;
	  }
	| {
			readonly kind: "unavailable";
			readonly reason: RespondersFailure | CertificateFailure;
			readonly detail: string;
			readonly cause?: unknown;
			readonly outage?: true;
			/** Epoch millis after which the responder is tried again. */
			readonly expiresAt: number;
	  };

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

const DEFAULT_MAX_CACHE_ENTRIES = 1024;

const issuerKeyId = (issuer: pkijs.Certificate): string =>
	createHash("sha256")
		.update(new Uint8Array(issuer.subjectPublicKeyInfo.toSchema().toBER(false)))
		.digest("hex");

const serialHex = (certificate: pkijs.Certificate): string =>
	Buffer.from(certificate.serialNumber.valueBlock.valueHexView).toString("hex");

const statusKey = (url: string, issuerId: string, serial: string): string =>
	`ocsp:${url}\n${issuerId}\n${serial}`;
const responderDownKey = (url: string): string => `down:${url}`;
const certificateDownKey = (url: string, issuerId: string, serial: string): string =>
	`down:${url}\n${issuerId}\n${serial}`;

export const createOcspResolver = (options: OcspResolverOptions): OcspResolver => {
	const cache = new Map<string, CacheEntry>();
	const maxEntries = options.maxCacheEntries ?? DEFAULT_MAX_CACHE_ENTRIES;
	const requireNonce = options.requireNonce ?? true;
	const algorithms = options.algorithms ?? DEFAULT_ALGORITHM_POLICY;
	/** Requests in progress, so concurrent misses on one certificate issue one request. */
	const inFlight = new Map<string, Promise<Answer>>();

	const store = (key: string, entry: CacheEntry): void => {
		if (cache.size >= maxEntries && !cache.has(key)) {
			// Oldest insertion first, as in `crl.mts`: the bound exists so the
			// map cannot grow without limit, not to maximise hits.
			const oldest = cache.keys().next();
			if (!oldest.done) cache.delete(oldest.value);
		}
		cache.set(key, entry);
	};

	const remember = (
		key: string,
		reason: RespondersFailure | CertificateFailure,
		failure: { readonly detail: string; readonly cause?: unknown; readonly outage?: true },
		now: Date,
	): void =>
		store(key, {
			kind: "unavailable",
			reason,
			detail: failure.detail,
			...(failure.cause !== undefined ? { cause: failure.cause } : {}),
			...(failure.outage ? { outage: true } : {}),
			expiresAt: now.getTime() + OCSP_NEGATIVE_CACHE_TTL_MS,
		});

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

	/** `query`, joining a request for the same certificate that is already in flight. */
	const load = (
		key: string,
		url: string,
		certificate: pkijs.Certificate,
		issuer: pkijs.Certificate,
		now: Date,
	): Promise<Answer> => {
		const existing = inFlight.get(key);
		if (existing !== undefined) return existing;
		const pending = query(url, certificate, issuer, now)
			.then(markOutage)
			.finally(() => inFlight.delete(key));
		inFlight.set(key, pending);
		return pending;
	};

	/** What `url` says about `certificate` — from the cache, or by asking now. */
	const lookup = async (
		url: string,
		certificate: pkijs.Certificate,
		issuer: pkijs.Certificate,
		issuerId: string,
		serial: string,
		now: Date,
	): Promise<Answer> => {
		const statusCacheKey = statusKey(url, issuerId, serial);
		const known = cache.get(statusCacheKey);
		if (known?.kind === "status" && known.expiresAt > now.getTime()) {
			// A cached answer from a delegated responder is only as good as that
			// responder still is: re-check it (the source behind the hook caches,
			// so this is cheap) and drop the entry if it has been revoked since.
			if (known.delegate !== undefined) {
				const verdict = await checkResponder(known.delegate, issuer, now);
				if (!verdict.ok) {
					cache.delete(statusCacheKey);
					return verdict;
				}
				return {
					ok: true,
					status: known.status,
					expiresAt: known.expiresAt,
					responderUnchecked: verdict.unchecked,
					delegate: known.delegate,
				};
			}
			return { ok: true, status: known.status, expiresAt: known.expiresAt };
		}
		for (const key of [responderDownKey(url), certificateDownKey(url, issuerId, serial)]) {
			const down = cache.get(key);
			if (down?.kind === "unavailable" && down.expiresAt > now.getTime()) {
				return {
					ok: false,
					reason: down.reason,
					detail: `${down.detail}; not retried yet`,
					...(down.cause !== undefined ? { cause: down.cause } : {}),
					...(down.outage ? { outage: true } : {}),
				};
			}
		}

		const answer = await load(`${url}\n${issuerId}\n${serial}`, url, certificate, issuer, now);
		if (answer.ok) {
			store(statusCacheKey, {
				kind: "status",
				status: answer.status,
				expiresAt: answer.expiresAt,
				...(answer.delegate === undefined ? {} : { delegate: answer.delegate }),
			});
			return answer;
		}
		if (RESPONDER_FAILURES.has(answer.reason)) {
			remember(responderDownKey(url), answer.reason as RespondersFailure, answer, now);
		} else if (CERTIFICATE_FAILURES.has(answer.reason)) {
			remember(
				certificateDownKey(url, issuerId, serial),
				answer.reason as CertificateFailure,
				answer,
				now,
			);
		}
		// `bad_signature` and `nonce_mismatch` are left unremembered on purpose.
		return answer;
	};

	return {
		size: () => cache.size,

		resolve: async (certificate, issuer, now) => {
			const responders = ocspResponders(certificate);
			if (!responders.ok) return responders;

			const issuerId = issuerKeyId(issuer);
			const serial = serialHex(certificate);
			const failures: OcspResponderUnavailable[] = [];
			for (const url of responders.urls) {
				const answer = await lookup(url, certificate, issuer, issuerId, serial, now);
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
