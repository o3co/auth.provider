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
 * `mode = "full-pki"` — RFC 5280 path validation with revocation, for issue
 * #341.
 *
 * ### Why this is not an extension of `pki.mts`
 *
 * The narrow mode in `pki.mts` is a synchronous hand-written walk that checks
 * what `node:crypto`'s `X509Certificate` happens to expose. Everything left
 * on #341's list — name constraints, the policy tree, `keyUsage` bits,
 * unrecognised critical extensions — needs the DER that class does not
 * surface, and revocation needs a fetch, which a synchronous function cannot
 * do. Both walls are hit at once, and RFC 8705 §7.5 says to delegate rather
 * than climb them: this arm hands path validation to `pkijs`, whose
 * `CertificateChainValidationEngine` implements RFC 5280 §6 including the
 * policy tree and name-constraint processing.
 *
 * The narrow mode is untouched. A deployment on `mode = "pki"` gets exactly
 * the behaviour it had.
 *
 * ### What this module owns, and why it is not all delegated
 *
 * Three things the engine does not do, in ascending order of how badly they
 * fail:
 *
 *  1. **`pathLenConstraint` (RFC 5280 §4.2.1.9).** Not implemented by the
 *     engine. Checked here against the validated path.
 *  2. **Algorithm policy (§6.1.4).** Left to local policy by the RFC, which
 *     in practice means the OpenSSL build's policy. Applied here to every
 *     certificate on the path, and by the resolvers to the CRL and OCSP
 *     signatures and to a delegated responder's certificate (#470).
 *  3. **Revocation.** The engine skips its revocation block entirely when
 *     handed no CRLs, and returns *valid*. So a CRL endpoint that is down
 *     produces the same verdict as a certificate that is not revoked. That is
 *     the single most dangerous default in this area, and it is the reason
 *     revocation is decided here, per certificate, rather than by one engine
 *     call with some CRLs attached.
 *
 * ### Why the engine validates the path but does not decide revocation
 *
 * Pass 1 hands the engine the presented chain with no revocation material and
 * takes back the validated path. Pass 2 walks that path — anchor excluded —
 * and, for each certificate, asks the resolver for the CRL its issuer
 * published and checks the serial against it. The resolver has already
 * verified the CRL's signature against that issuer (`crl.mts`), so the
 * lookup is one comparison and the engine is not consulted again.
 *
 * It used to be. The engine takes CRLs as one flat list and applies one rule
 * to the whole path: a certificate with no usable CRL is refused whenever
 * its issuer advertises a distribution point, regardless of
 * `passedWhenNotRevValues`. That is the wrong shape for an operator policy
 * meant to apply per certificate — with the leaf's distribution point down
 * and the intermediate's up, the common outage, `"allow"` refused — and it
 * meant a CRL the engine discarded for a bad signature never reached the
 * logged availability branch. Deciding here makes `on-unavailable` mean what
 * the configuration says: `"reject"` refuses a certificate whose status is
 * unknown — or only partly known, because one of the distribution points it
 * names could not be used (#446) — `"allow"` skips exactly those
 * certificates and logs each one once the whole path has passed (a request
 * refused for another certificate used no soft-fail, and has its refusal's
 * lines alone), and a status that *was* determined as revoked is refused
 * under both.
 *
 * Under `"reject"` an unknown status is one of two things. When every source
 * behind it failed to answer usefully — an outage, as `crl.mts` and
 * `ocsp.mts` mark it — the refusal is the server's: the result says
 * `outage`, this validator writes no line, and the mechanism refuses it
 * `unavailable`, which core's dispatcher answers 503 and logs once. Anything
 * else is the certificate's own shape, a verdict, refused and logged here as
 * before. A verdict anywhere on the path wins over an outage: the outage is
 * held until every certificate has been judged, and then it is the whole
 * path's — one refusal whose cause names every source that could not be
 * used, for every certificate on the path, so an operator sees the next
 * source down before fixing the first.
 *
 * The ordering — validate, then fetch — is a security property, not an
 * optimisation. A distribution point is a URL inside a certificate, and
 * fetching it makes this process issue a request to a destination someone
 * else chose. Validating first means only a certificate that already chains
 * to a configured trust anchor can cause an outbound request at all — an
 * arbitrary certificate presented by an arbitrary client cannot.
 * `fetchGuard.mts` holds the second layer.
 *
 * ### OCSP, and `mode = "both"` (#431)
 *
 * OCSP (RFC 6960) takes the same slot: `ocsp.mts` asks the responders a
 * certificate names and hands back a status, or an unavailability with a
 * reason, and the decision below is the same one — a determined *revoked*
 * refuses under both policies, an unavailable status is the operator's
 * `on-unavailable` call. It is responder-fetch only: the "stapled OCSP is
 * the cheap path under `tls-layer`" idea in #341 does not survive contact
 * with Node, where `status_request` stapling covers the *server's*
 * certificate and nothing is exposed for a **client** certificate. A leaf
 * that carries OCSP must-staple (RFC 7633) is refused for exactly that
 * reason, before any responder is asked.
 *
 * Under `"both"` the responder is asked first — one small request about one
 * certificate, against a CRL that may be large — and the CRL is consulted
 * only when OCSP could not answer: unreachable, unverifiable, stale, or
 * simply not named. An `unknown` is an answer, not an outage (#471), and it
 * is the one shape where both sources are consulted: the CRL cannot list a
 * never-issued serial, so it cannot clear one, but it can still refuse one.
 * A CRL that lists the certificate therefore decides it; a CRL that does not
 * has said nothing, and the `unknown` stands. A *revoked* from either source
 * wins; a certificate is unavailable when both sources are, or when the
 * responder said `unknown` and the CRL did not list it. The fallback is logged
 * when a responder was actually asked and failed, the CRL then answered, and
 * the mechanism accepted the certificate on that answer — its whole path
 * passed — so an OCSP outage is visible even while the CRL keeps revocation
 * checking alive. The line says what the mechanism accepted, no more: the
 * request can still be refused afterwards, by another mechanism, the grant
 * or a protected resource's binding check. `decide` hands the notice back
 * rather than writing it, because whether the certificate is accepted is the
 * whole path's to say: it is written once every certificate has passed. A
 * path refused for another certificate's outage names the failed responder
 * among the outage's members instead, and a path refused as a verdict has
 * that verdict's lines. When the CRL does not answer either, the one line is
 * the unavailability's — the dispatcher's outage line under `"reject"`, the
 * allowed line under `"allow"` — naming both sources and carrying both
 * errors (an AggregateError, OCSP's first).
 */

import { X509Certificate } from "node:crypto";
import { loggableError } from "@o3co/auth-provider-core";
import * as pkijs from "pkijs";
import { MtlsRevocationSourceError, MtlsRevocationUnavailableError } from "../errors.mjs";
import { checkClientLeafProfile } from "../pki.mjs";
import { type AlgorithmPolicy, checkAlgorithmPolicy } from "./algorithms.mjs";
import { checkCriticalExtensions, checkLeafKeyUsage } from "./criticalExtensions.mjs";
import {
	type CrlPointUnavailable,
	type CrlResolver,
	createCrlResolver,
	describeUnavailable,
} from "./crl.mjs";
import { createGuardedFetch } from "./fetchGuard.mjs";
import { checkMustStaple, createOcspResolver, type OcspResolver } from "./ocsp.mjs";
import { subjectLine } from "./subject.mjs";

/** OID of `basicConstraints` (RFC 5280 §4.2.1.9). */
const OID_BASIC_CONSTRAINTS = "2.5.29.19";

export interface Logger {
	warn(obj: Record<string, unknown>, msg: string): void;
	debug?(obj: Record<string, unknown>, msg: string): void;
}

/**
 * What to do when revocation status cannot be determined.
 *
 * There is no default. "The CRL endpoint is unreachable" and "the certificate
 * is not revoked" are different facts, and which one a deployment is willing
 * to act on depends on whether an outage that blocks logins is worse than a
 * window in which a revoked certificate still works. A library that picks for
 * the operator picks wrong for half of them, silently.
 */
export type OnRevocationUnavailable = "reject" | "allow";

/**
 * Where revocation status comes from. `"both"` asks the responder first and
 * falls back to the CRL when OCSP could not answer (#431) — could not, not would not. An OCSP `unknown` is an answer (#471): the CRL is asked but may only refuse, never clear.
 */
export type RevocationSource = "crl" | "ocsp" | "both";

export type RevocationPolicy =
	| { readonly mode: "disabled" }
	| {
			readonly mode: RevocationSource;
			readonly onUnavailable: OnRevocationUnavailable;
			readonly allowedHosts: readonly string[];
			readonly fetchTimeoutMs: number;
			readonly cacheTtlSeconds: number;
			readonly maxResponseBytes: number;
			/**
			 * OCSP only: refuse a response that does not echo the request's
			 * nonce. Defaults to `true` (RFC 8954); `false` is for a responder
			 * that pre-produces its answers, and gives up replay protection
			 * within the response's own validity window.
			 */
			readonly ocspRequireNonce?: boolean;
	  };

export interface FullPkiOptions {
	readonly trustedCas: readonly X509Certificate[];
	readonly algorithms: AlgorithmPolicy;
	/** Maximum certificates in a path, leaf and anchor included. */
	readonly maxChainDepth: number;
	readonly revocation: RevocationPolicy;
	readonly logger?: Logger;
	/** Injected in tests. */
	readonly fetchImpl?: typeof globalThis.fetch;
}

/**
 * The verdict. A refusal names its `step` and a `detail` in this module's own
 * words; `cause` is the library error behind it, when one threw — pkijs,
 * WebCrypto, the platform fetch — as it was thrown, and never its text in
 * `detail`. Whoever logs the refusal logs core's `loggableError` projection of
 * `cause` as `err`, and nothing else of it.
 */
export type FullPkiResult =
	| { readonly ok: true }
	| {
			readonly ok: false;
			readonly step: string;
			readonly detail: string;
			readonly cause?: unknown;
			/**
			 * Set when the refusal is the server's outage, not a verdict on the
			 * certificate: under `on-unavailable = "reject"`, the only thing that
			 * stopped the path was a revocation source that did not deliver a
			 * usable answer (see `crl.mts`, "An outage, or the certificate's
			 * shape"). The mechanism refuses it `unavailable` — `503` from the
			 * dispatcher, which writes its one line — and this validator writes
			 * none. `cause` is then an `MtlsRevocationUnavailableError`, one
			 * member per source that could not be used, for every certificate on
			 * the path.
			 */
			readonly outage?: true;
	  };

export interface FullPkiValidator {
	validate(
		leaf: X509Certificate,
		chain: readonly X509Certificate[],
		now: Date,
	): Promise<FullPkiResult>;
	/**
	 * Entries in the CRL cache, usable and remembered-unavailable alike.
	 * Exposed for tests and for a future cache-size metric.
	 */
	readonly crlCacheSize: () => number;
	/** The same for the OCSP cache. */
	readonly ocspCacheSize: () => number;
}

/**
 * One certificate's revocation outcome, whatever source produced it. The
 * policy below acts on the kind alone, so OCSP and CRL land in the same
 * decision with the same strictness.
 */
type RevocationOutcome =
	| { readonly kind: "revoked"; readonly detail: string }
	| {
			readonly kind: "determined";
			/** CRL distribution points that could not be used, for the per-point strictness (#446). */
			readonly unavailable: readonly CrlPointUnavailable[];
			/**
			 * Under `"both"`, the responder that was asked and failed before the
			 * CRL's answer was served. Written as `mtls_revocation_ocsp_fallback`
			 * only once the whole path has passed; folded into an outage's
			 * members when another certificate's status could not be determined.
			 */
			readonly fallback?: FallbackNotice;
	  }
	| {
			readonly kind: "unavailable";
			readonly reason: string;
			readonly detail: string;
			/** The library error behind `reason`, when one threw. */
			readonly cause?: unknown;
			/** Every source asked failed because it did not answer usefully. */
			readonly outage?: true;
			/** Each source that could not be used, one by one — what an outage's cause is built from. */
			readonly failures: readonly SourceFailure[];
	  };

/** One revocation source — a CRL distribution point or an OCSP responder — that could not be used. */
interface SourceFailure {
	readonly source: "crl" | "ocsp";
	readonly url?: string;
	readonly reason: string;
	readonly detail: string;
	readonly cause?: unknown;
}

/** The OCSP failure a certificate's CRL answer was served over, under `"both"`. */
interface FallbackNotice {
	readonly reason: string;
	readonly detail: string;
	readonly cause?: unknown;
	readonly failures: readonly SourceFailure[];
}

/**
 * A line for a certificate the mechanism accepted — its whole path passed —
 * on the soft-fail or the fallback: one admitted under `"allow"` with its
 * status unknown or only partly known, or one whose CRL answer was used over
 * a responder that failed. Held until the whole path has passed, and then
 * written in path order: a path refused for another certificate accepted
 * nothing on either, and its refusal's lines are its account. The line says
 * no more than that: the request can still be refused afterwards, by another
 * mechanism's verdict or `strict-mutual-exclusion`, by the grant, or at a
 * protected resource by `no_matching_binding`.
 */
interface PendingLine {
	readonly event:
		| "mtls_revocation_unavailable_allowed"
		| "mtls_revocation_partially_unavailable_allowed"
		| "mtls_revocation_ocsp_fallback";
	readonly subject: string;
	readonly reason: string;
	readonly detail: string;
	readonly cause?: unknown;
}

/** A CRL distribution point that could not be used, as a {@link SourceFailure}. */
const pointFailure = (point: CrlPointUnavailable): SourceFailure => ({
	source: "crl",
	url: point.url,
	reason: point.reason,
	detail: point.detail,
	...withCause(point.cause),
});

/** A source that could not be used, and the certificate it was asked about. */
interface OutageMember {
	readonly subject: string;
	readonly failure: SourceFailure;
}

/**
 * The cause of an outage refusal: one short error per source that could not
 * be used, each naming its certificate last — so a log line's cap on a
 * projected message cuts no source's account — in path order, leaf first.
 * `subjects` are the certificates whose status could not be determined.
 */
const revocationUnavailable = (
	subjects: readonly string[],
	members: readonly OutageMember[],
): MtlsRevocationUnavailableError =>
	new MtlsRevocationUnavailableError(
		subjects,
		members.map(
			({ subject, failure }) =>
				new MtlsRevocationSourceError(
					{ ...failure, subject },
					failure.cause !== undefined ? { cause: failure.cause } : undefined,
				),
		),
	);

/** `{ cause }` when there is one, for a spread into an outcome or a result. */
const withCause = (cause: unknown): { cause?: unknown } => (cause !== undefined ? { cause } : {});

/** `{ err }`, the projection of `cause`, when there is one — for a log line. */
const errOf = (cause: unknown): { err?: ReturnType<typeof loggableError> } =>
	cause !== undefined ? { err: loggableError(cause) } : {};

const toPkijs = (certificate: X509Certificate): pkijs.Certificate =>
	pkijs.Certificate.fromBER(certificate.raw);

const toNode = (certificate: pkijs.Certificate): X509Certificate =>
	new X509Certificate(Buffer.from(certificate.toSchema(true).toBER(false)));

/** The certificate's subject on one line ({@link subjectLine}), as every line and detail here names it. */
const subjectOf = (certificate: pkijs.Certificate): string => subjectLine(toNode(certificate));

/**
 * `pathLenConstraint` bounds how many CA certificates may appear *below* a
 * CA in a path (RFC 5280 §4.2.1.9). `path` is leaf-first, so for the
 * certificate at index `i` the certificates below it are `0 … i-1`, of which
 * exactly one — the leaf — is not a CA. Hence `i - 1` intermediates.
 *
 * The engine does not implement this, so a CA that published `pathlen:0`
 * precisely to stop sub-CAs from being minted under it would otherwise have
 * said so for nothing.
 */
const checkPathLength = (path: readonly pkijs.Certificate[]): FullPkiResult => {
	for (let i = 1; i < path.length; i++) {
		const certificate = path[i];
		if (certificate === undefined) continue;
		const extension = certificate.extensions?.find((ext) => ext.extnID === OID_BASIC_CONSTRAINTS);
		const parsed = extension?.parsedValue as pkijs.BasicConstraints | undefined;
		if (parsed?.cA !== true) continue;
		const raw = parsed.pathLenConstraint;
		if (raw === undefined) continue;
		const limit = typeof raw === "number" ? raw : Number(raw.valueBlock.valueDec);
		const intermediatesBelow = i - 1;
		if (intermediatesBelow > limit) {
			return {
				ok: false,
				step: "pathLenConstraint exceeded",
				detail:
					`a CA at depth ${i} permits ${limit} intermediate CA(s) below it, ` +
					`but the presented path has ${intermediatesBelow}`,
			};
		}
	}
	return { ok: true };
};

/**
 * This package's words for the result codes the engine can answer with here
 * (pkijs 3.4): its path checks — 8 (validity), 9 (path length), 10 (name
 * chaining), 14 (a certificate above the leaf failed its CA check:
 * basicConstraints, keyUsage or an unparseable critical extension; the finer
 * codes 3–7 that check computes never reach the result) — and its policy and
 * name-constraint checks (21, 41, 42, 98, 99). The engine runs without
 * revocation material, so its revocation codes (11–13) cannot occur;
 * revocation outcomes are named by the local pass below. The engine's
 * `resultMessage` is never used — it is the library's text, and for an
 * error it caught, that error's message.
 */
const ENGINE_FAILURE_DETAIL: Readonly<Record<number, string>> = {
	8: "a certificate on the path is not yet valid or has expired",
	9: "the path is too short",
	10: "issuer and subject names on the path do not chain",
	14: "a certificate on the path above the leaf is not a CA certificate",
	21: "a name form a name constraint requires is missing",
	41: "a name on the path is outside the permitted subtrees of a name constraint",
	42: "a name on the path is inside an excluded subtree of a name constraint",
	98: "a certificate policy mapping is prohibited on the path",
	99: "a certificate policy mapping maps anyPolicy",
};

/**
 * Map the engine's outcome onto a short step name the audit trail can carry,
 * a detail in this package's words, and the Error the engine caught, if any.
 *
 * "No path to a trust anchor" — the single most common misconfiguration —
 * arrives two ways: as pkijs's own `ChainValidationError` (`noPath`,
 * `noValidPath`), or as a plain `Error` its path builder throws when a
 * certificate has no issuer among those it was given, which the engine maps
 * onto `unknown`. The second is recognised by `noIssuer` — the issuer lookup
 * came back empty, which the validator observes through the engine's
 * `findIssuer` hook — not by the message, which is pkijs's text.
 */
const describeEngineFailure = (
	result: { readonly resultCode: number; readonly error?: unknown },
	noIssuer: boolean,
): { step: string; detail: string; cause?: unknown } => {
	const cause = result.error !== undefined ? { cause: result.error } : {};
	if (
		// The empty issuer lookup is read only where the builder's plain Error
		// lands (`unknown`): a refusal with a code of its own is that code's.
		(noIssuer && result.resultCode === pkijs.ChainValidationCode.unknown) ||
		result.resultCode === pkijs.ChainValidationCode.noPath ||
		result.resultCode === pkijs.ChainValidationCode.noValidPath
	) {
		return {
			step: "no path to trust anchor",
			detail: "no certificate path reaches a configured trust anchor",
			...cause,
		};
	}
	const detail =
		ENGINE_FAILURE_DETAIL[result.resultCode] ??
		(result.resultCode === pkijs.ChainValidationCode.unknown
			? "the path validation engine failed"
			: `the path validation engine refused the path (code ${result.resultCode})`);
	return { step: "path validation failed", detail, ...cause };
};

export const createFullPkiValidator = (options: FullPkiOptions): FullPkiValidator => {
	const trustedCerts = options.trustedCas.map(toPkijs);
	const revocation = options.revocation;

	// One guarded fetch serves both resolvers: the allowlist, timeout and
	// byte cap are properties of what this process may retrieve, not of
	// which revocation mechanism asked.
	const fetch =
		revocation.mode === "disabled"
			? null
			: createGuardedFetch({
					allowedHosts: revocation.allowedHosts,
					timeoutMs: revocation.fetchTimeoutMs,
					maxBytes: revocation.maxResponseBytes,
					...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
				});
	// The same algorithm policy the path is held to governs the revocation
	// material about it — a CRL's signature, a response's signature, a
	// delegated responder's certificate (#470). One policy, or a deployment
	// that refuses SHA-1 certificates would still believe SHA-1 CRLs.
	const crlResolver: CrlResolver | null =
		fetch !== null && revocation.mode !== "disabled" && revocation.mode !== "ocsp"
			? createCrlResolver({
					fetch,
					cacheTtlSeconds: revocation.cacheTtlSeconds,
					algorithms: options.algorithms,
				})
			: null;
	const ocspResolver: OcspResolver | null =
		fetch !== null && revocation.mode !== "disabled" && revocation.mode !== "crl"
			? createOcspResolver({
					fetch,
					cacheTtlSeconds: revocation.cacheTtlSeconds,
					algorithms: options.algorithms,
					...(revocation.ocspRequireNonce === undefined
						? {}
						: { requireNonce: revocation.ocspRequireNonce }),
					// #468: under "both" the CA's CRL is the independent source a
					// delegated responder without `nocheck` is checked against — the
					// CRL the responder's own certificate names. One naming none is
					// the CA specifying no method (RFC 6960 §4.2.2.2.1, third option):
					// local policy, which is to take the answer and log it, rather than
					// to turn `both` into `crl` for every deployment whose responder
					// certificate carries no distribution point.
					...(crlResolver !== null
						? {
								responderRevocation: async (responder, issuer, now) => {
									const own = await byCrl(responder, issuer, now);
									if (own.kind === "unavailable") {
										return own.reason === "no_distribution_point" ? { kind: "unspecified" } : own;
									}
									// #550: a CRL the resolver could only partly use does not
									// say the responder is clean — it is the same partial answer
									// `on-unavailable` judges for any certificate (#446), and a
									// responder is not the place to guess in the permissive
									// direction: its answer is discarded and the leaf falls back
									// to its own CRL.
									if (own.kind === "determined" && own.unavailable.length > 0) {
										const last = own.unavailable[own.unavailable.length - 1] as CrlPointUnavailable;
										return {
											kind: "unavailable",
											reason: last.reason,
											detail: describeUnavailable(own.unavailable),
											...withCause(last.cause),
											...(own.unavailable.every((point) => point.outage) ? { outage: true } : {}),
											failures: own.unavailable.map(pointFailure),
										};
									}
									return own;
								},
							}
						: {}),
				})
			: null;
	// #468: responders taken without a check, so the deviation is logged once each.
	const uncheckedResponders = new Set<string>();

	const byCrl = async (
		certificate: pkijs.Certificate,
		issuer: pkijs.Certificate,
		now: Date,
	): Promise<RevocationOutcome> => {
		const lookup = await (crlResolver as CrlResolver).resolve(certificate, issuer, now);
		if (!lookup.ok) {
			return {
				kind: "unavailable",
				reason: lookup.reason,
				detail: lookup.detail,
				...withCause(lookup.cause),
				...(lookup.outage ? { outage: true } : {}),
				failures: lookup.points?.map(pointFailure) ?? [
					{
						source: "crl",
						reason: lookup.reason,
						detail: lookup.detail,
						...withCause(lookup.cause),
					},
				],
			};
		}
		// Every CRL here verified against `issuer`, whose subject is this
		// certificate's issuer name, so the serial comparison is the whole
		// check.
		if (lookup.crls.some((crl) => crl.isCertificateRevoked(certificate))) {
			return {
				kind: "revoked",
				detail: `${subjectOf(certificate)}: listed on the CRL published by ${subjectOf(issuer)}`,
			};
		}
		return { kind: "determined", unavailable: lookup.unavailable };
	};

	const byOcsp = async (
		certificate: pkijs.Certificate,
		issuer: pkijs.Certificate,
		now: Date,
	): Promise<RevocationOutcome> => {
		const lookup = await (ocspResolver as OcspResolver).resolve(certificate, issuer, now);
		if (!lookup.ok) {
			return {
				kind: "unavailable",
				reason: lookup.reason,
				detail: lookup.detail,
				...withCause(lookup.cause),
				...(lookup.outage ? { outage: true } : {}),
				failures: lookup.responders?.map(
					(responder): SourceFailure => ({
						source: "ocsp",
						url: responder.url,
						reason: responder.reason,
						detail: responder.detail,
						...withCause(responder.cause),
					}),
				) ?? [
					{
						source: "ocsp",
						reason: lookup.reason,
						detail: lookup.detail,
						...withCause(lookup.cause),
					},
				],
			};
		}
		if (lookup.responderUnchecked && !uncheckedResponders.has(lookup.responder)) {
			uncheckedResponders.add(lookup.responder);
			options.logger?.warn(
				{ responder: lookup.responder, subject: subjectOf(certificate) },
				"mtls_ocsp_responder_unchecked",
			);
		}
		if (lookup.status.status === "revoked") {
			const reason = lookup.status.reason === undefined ? "" : ` (${lookup.status.reason})`;
			return {
				kind: "revoked",
				detail:
					`${subjectOf(certificate)}: reported revoked at ` +
					`${lookup.status.revokedAt.toISOString()}${reason} by the OCSP responder at ` +
					lookup.responder,
			};
		}
		return { kind: "determined", unavailable: [] };
	};

	/**
	 * The certificate's status from the configured source(s). Under `"both"`
	 * the responder goes first and the CRL is consulted when it could not
	 * answer — could not, not would not. An OCSP `unknown` is an answer
	 * (#471), and the CRL is asked about it too but may only refuse: it
	 * cannot list a never-issued serial, so it cannot clear one. A status
	 * either source determined is final, and the certificate is unavailable
	 * only when both are, or when the responder said `unknown` and the CRL
	 * did not list it.
	 */
	const decide = async (
		certificate: pkijs.Certificate,
		issuer: pkijs.Certificate,
		now: Date,
	): Promise<RevocationOutcome> => {
		if (revocation.mode === "crl") return byCrl(certificate, issuer, now);
		if (revocation.mode === "ocsp") return byOcsp(certificate, issuer, now);
		const ocsp = await byOcsp(certificate, issuer, now);
		if (ocsp.kind !== "unavailable") return ocsp;
		// #471: `unknown` is an answer, not an outage. RFC 6960 §2.2: the
		// responder does not know the certificate — for a serial the CA never
		// issued, that is the whole finding — and a CRL cannot list a
		// never-issued serial, so it cannot exonerate one. A CRL's *silence*
		// about this certificate therefore decides nothing, and the `unknown`
		// stands for `on-unavailable` to judge.
		//
		// It can still say `revoked`, and that is worth asking for: a combined
		// mode must not refuse fewer certificates than either of its parts.
		// `crl` alone refuses a certificate its CRL lists; before this, `both`
		// admitted the same certificate under `allow`, because the list that
		// names it was never consulted.
		if (ocsp.reason === "unknown") {
			const listed = await byCrl(certificate, issuer, now);
			if (listed.kind === "revoked") return listed;
			return ocsp;
		}
		const crl = await byCrl(certificate, issuer, now);
		// The fallback's answer is served when it settles the certificate —
		// revoked, or determined from every point it names — or when it is a
		// partial answer the policy takes ("allow"). Under "reject" a partial
		// answer is no answer: the loop below would refuse it, so it is folded
		// together with the OCSP failure here, as when the CRL did not answer
		// at all.
		const served =
			crl.kind === "revoked" ||
			(crl.kind === "determined" &&
				(crl.unavailable.length === 0 ||
					("onUnavailable" in revocation && revocation.onUnavailable === "allow")));
		if (served) {
			// A degraded answer. The responder that was asked and did not answer
			// is handed back as a notice, so an OCSP outage stays visible while
			// the CRL carries on — written by `validate` once the whole path has
			// passed, since a path refused for another certificate accepted
			// nothing on this fallback. A revoked certificate is a verdict and has
			// the verdict's lines. A certificate that names no responder is a
			// normal shape under "both" — a CA that publishes only CRLs for some
			// of its certificates — not an outage, and has no notice.
			if (crl.kind === "determined" && ocsp.reason !== "no_responder") {
				return {
					...crl,
					fallback: {
						reason: ocsp.reason,
						detail: ocsp.detail,
						...withCause(ocsp.cause),
						failures: ocsp.failures,
					},
				};
			}
			return crl;
		}
		// Neither source gave an answer that is served. No fallback line: the
		// unavailability below is the one account of it — the dispatcher's
		// outage line, or this validator's rejected or allowed line — and it
		// names both sources.
		const gaps = crl.kind === "determined" ? crl.unavailable : [];
		const crlSide =
			crl.kind === "unavailable"
				? crl
				: {
						reason: (gaps[gaps.length - 1] as CrlPointUnavailable).reason,
						detail: describeUnavailable(gaps),
						cause: gaps[gaps.length - 1]?.cause,
						outage: gaps.every((point) => point.outage) ? (true as const) : undefined,
						failures: gaps.map(pointFailure),
					};
		// An outage when every source the certificate names failed as one; a
		// source it names none of (no responder, no distribution point) was
		// never asked, and says nothing either way — nor is it a member of the
		// outage's cause, where it would spend one of the slots a log line keeps.
		const asked = [ocsp, crlSide].filter(
			(source) => source.reason !== "no_responder" && source.reason !== "no_distribution_point",
		);
		// `reason` is the CRL's, the last source asked. The errors are both
		// sources', OCSP's first: an AggregateError of the two when both
		// threw — its members are what a warn line projects — else the one
		// that did. An outage's refusal is built from `failures` instead.
		const causes = [ocsp.cause, crlSide.cause].filter((cause) => cause !== undefined);
		const cause =
			causes.length > 1
				? new AggregateError(causes, "neither revocation source answered: OCSP, then the CRL")
				: causes[0];
		return {
			kind: "unavailable",
			reason: crlSide.reason,
			detail: `ocsp: ${ocsp.reason} (${ocsp.detail}); crl: ${crlSide.reason} (${crlSide.detail})`,
			...withCause(cause),
			...(asked.length > 0 && asked.every((source) => source.outage) ? { outage: true } : {}),
			failures: asked.flatMap((source) => source.failures),
		};
	};

	return {
		crlCacheSize: () => crlResolver?.size() ?? 0,
		ocspCacheSize: () => ocspResolver?.size() ?? 0,

		validate: async (leaf, chain, now) => {
			// Bound the work before any signature is verified: a caller-supplied
			// chain is attacker-influenced input, and path building is quadratic
			// in its length.
			const presented = 1 + chain.length;
			if (presented > options.maxChainDepth) {
				return {
					ok: false,
					step: "chain too long",
					detail: `${presented} certificates presented, limit is ${options.maxChainDepth}`,
				};
			}

			// Order matters, and not in the way the parameter name suggests:
			// `CertificateChainValidationEngine` takes the **last** element of
			// `certs` as the end entity and builds upward from it. Passing the
			// leaf first silently validates the first intermediate instead — the
			// engine reports success, the returned path is short by one, and
			// every leaf-specific check (name constraints, the leaf's own
			// revocation status) is skipped on a certificate that was never
			// examined. It fails open and it fails quietly, so the leaf goes last
			// and `path[0]` below is asserted to be it.
			const certs = [...chain.map(toPkijs), toPkijs(leaf)];

			// --- Pass 1: path validation, no revocation material. ---
			//
			// `passedWhenNotRevValues: true` here is not a policy choice — no CRLs
			// are supplied, so the engine's revocation block does not run at all.
			// The flag only keeps the engine from objecting to their absence.
			let noIssuer = false;
			const engine = new pkijs.CertificateChainValidationEngine({
				trustedCerts,
				certs,
				checkDate: now,
				// The default lookup, observed: an empty answer is the one case in
				// which the path builder throws its plain, code-less Error, and it
				// is how "no path to a trust anchor" is told apart from any other
				// Error the engine catches (`describeEngineFailure`).
				findIssuer: async (certificate, validationEngine, crypto) => {
					const issuers = await validationEngine.defaultFindIssuer(
						certificate,
						validationEngine,
						crypto,
					);
					if (issuers.length === 0) noIssuer = true;
					return issuers;
				},
			});

			let first: Awaited<ReturnType<pkijs.CertificateChainValidationEngine["verify"]>>;
			try {
				first = await engine.verify({ passedWhenNotRevValues: true });
			} catch (err) {
				// pkijs 3 catches inside `verify` and answers a result instead; this
				// is for a version that does not. The error is the library's.
				return {
					ok: false,
					step: "path validation failed",
					detail: "the path validation engine failed",
					cause: err,
				};
			}
			if (!first.result) {
				return { ok: false, ...describeEngineFailure(first, noIssuer) };
			}

			const path = first.certificatePath ?? [];
			if (path.length === 0) {
				return {
					ok: false,
					step: "no path to trust anchor",
					detail: "engine reported success without returning a path",
				};
			}
			// The engine returns the path leaf-first. Everything below indexes on
			// that — `checkPathLength` counts intermediates as `i - 1`, and the
			// revocation pass drops the last element as the anchor — so a future
			// version of the library reversing it must not pass silently.
			if (
				Buffer.compare(
					Buffer.from(path[0]?.tbsView ?? []),
					Buffer.from(certs[certs.length - 1]?.tbsView ?? []),
				) !== 0
			) {
				return {
					ok: false,
					step: "path validation failed",
					detail: "validated path does not begin at the presented leaf certificate",
				};
			}

			// --- Checks the engine leaves to local policy, or skips on the leaf. ---
			const critical = checkCriticalExtensions(path);
			if (!critical.ok) return critical;

			const leafKeyUsage = checkLeafKeyUsage(path[0] as pkijs.Certificate);
			if (!leafKeyUsage.ok) return leafKeyUsage;

			// The same client-certificate profile the narrow mode applies —
			// `CA:FALSE` and, when present, an `extendedKeyUsage` naming
			// `clientAuth`. Imported rather than restated: a stricter mode that
			// quietly dropped a check the weaker mode makes would be the worst
			// possible shape for this pair, and two copies of the rule is how
			// that happens.
			const leafProfile = checkClientLeafProfile(leaf);
			if (!leafProfile.ok) {
				return { ok: false, step: leafProfile.step, detail: leafProfile.step };
			}

			// A leaf demanding a stapled OCSP response (RFC 7633) asks for
			// something no server can give a client certificate in Node. Its
			// own requirement cannot be met, so it is refused here — under
			// every revocation mode — rather than quietly treated as unstapled.
			const staple = checkMustStaple(path[0] as pkijs.Certificate);
			if (!staple.ok) return staple;

			const pathLength = checkPathLength(path);
			if (!pathLength.ok) return pathLength;

			for (const certificate of path) {
				const check = checkAlgorithmPolicy(
					toNode(certificate),
					certificate.signatureAlgorithm.algorithmId,
					options.algorithms,
				);
				if (!check.ok) return { ok: false, step: check.step, detail: check.detail };
			}

			if (revocation.mode === "disabled") return { ok: true };

			// --- Pass 2: revocation over the *validated* path, decided here. ---
			//
			// The trust anchor is excluded: nothing in the path can revoke it, and
			// an operator removing a compromised anchor from `trusted-cas` is the
			// mechanism that actually applies there.
			//
			// The next element up the path issued each certificate, so it is the
			// key its CRL, or the responder's answer, must verify against — the
			// resolvers refuse to hand back, or cache, anything that does not.
			//
			// Every lookup is issued at once. Awaiting them one after another
			// would make the token endpoint's latency during an outage the *sum*
			// of the distribution points' timeouts rather than the largest.
			const subjects = path.slice(0, -1);
			const outcomes = await Promise.all(
				subjects.map((certificate, index) =>
					decide(certificate, path[index + 1] as pkijs.Certificate, now),
				),
			);
			// Under "reject", an outage — a source that did not answer usefully —
			// is the server's, answered 503, and it is held until every
			// certificate has been judged: a certificate on the path that is
			// revoked, or whose status cannot be determined for a reason of its
			// own, is a verdict a retry would not change, and it wins. When
			// nothing else refused, the outage is returned for the whole path:
			// every certificate whose status could not be determined, and every
			// source that could not be used — a responder the CRL was served over
			// included — in path order.
			const outages: { readonly subject: string; readonly account: string }[] = [];
			const members: OutageMember[] = [];
			const memberOf =
				(subject: string) =>
				(failure: SourceFailure): OutageMember => ({ subject, failure });
			// Under "allow", and for a fallback used under either policy, the
			// lines for what the mechanism accepted wait for the path's result.
			const pending: PendingLine[] = [];
			for (const [index, certificate] of subjects.entries()) {
				const outcome = outcomes[index] as RevocationOutcome;

				// A status that *was* determined is not softened by the policy —
				// "allow" covers an unknown status, not a known-revoked one — and
				// it is consulted before any gap is judged: a CRL that was
				// obtained and lists this certificate, or a responder that said
				// so, settles the matter under both policies, whatever the
				// certificate's other sources did. Refusing such a certificate as
				// "unavailable" instead would tell the audit trail an outage where
				// there was a revocation.
				if (outcome.kind === "revoked") {
					return { ok: false, step: "certificate revoked", detail: outcome.detail };
				}

				if (outcome.kind === "unavailable") {
					const subject = subjectOf(certificate);
					if (revocation.onUnavailable === "reject" && outcome.outage) {
						// Not logged here: the dispatcher that answers the 503 writes the
						// outage's one line, with the cause built below.
						outages.push({ subject, account: `${outcome.reason} — ${outcome.detail}` });
						members.push(...outcome.failures.map(memberOf(subject)));
						continue;
					}
					if (revocation.onUnavailable === "reject") {
						options.logger?.warn(
							{ subject, reason: outcome.reason, detail: outcome.detail, ...errOf(outcome.cause) },
							"mtls_revocation_unavailable_rejected",
						);
						return {
							ok: false,
							step: "revocation status unavailable",
							detail: `${subject}: ${outcome.reason} — ${outcome.detail}`,
							...withCause(outcome.cause),
						};
					}
					// Soft-fail. Logged at warn, never silently: an operator who chose
					// "allow" still needs to see how often it is being used, because a
					// permanent soft-fail is an unrevocable PKI wearing a revocation
					// configuration. Logged once the path has passed: a path another
					// certificate's revocation refuses accepted nothing on the soft-fail.
					pending.push({
						event: "mtls_revocation_unavailable_allowed",
						subject,
						reason: outcome.reason,
						detail: outcome.detail,
						...withCause(outcome.cause),
					});
					continue;
				}

				// Served on the CRL over a responder that failed: the notice waits
				// for the path's result — written if the path passes, a member of
				// the outage if another certificate's status could not be
				// determined, nothing beside a verdict's own lines.
				if (outcome.fallback !== undefined) {
					const subject = subjectOf(certificate);
					pending.push({
						event: "mtls_revocation_ocsp_fallback",
						subject,
						reason: outcome.fallback.reason,
						detail: outcome.fallback.detail,
						...withCause(outcome.fallback.cause),
					});
					members.push(...outcome.fallback.failures.map(memberOf(subject)));
				}

				// Only a certificate absent from every CRL that was obtained is
				// subject to the gap. A certificate may name several distribution
				// points, and the resolver reports the ones it could not use —
				// down, or of a shape it does not implement (#469) — alongside
				// the CRLs it did obtain. Whether that partial answer is an
				// answer is this policy's call, not the resolver's (#446). Under
				// "reject" it is not: this process cannot tell from one fetched
				// CRL that the CA's other points were redundant — a CA that
				// partitions its list without saying so publishes exactly this
				// shape — and "reject" is the operator's instruction not to
				// guess in the permissive direction. Under "allow" that guess is
				// what was chosen, so the certificate passes and the gap is logged
				// once the path has — under its own message, because "checked
				// against part of its revocation material" and "not checked at
				// all" are different facts on an operator's dashboard.
				if (outcome.unavailable.length > 0) {
					const subject = subjectOf(certificate);
					const last = outcome.unavailable[outcome.unavailable.length - 1] as CrlPointUnavailable;
					const detail = describeUnavailable(outcome.unavailable);
					if (
						revocation.onUnavailable === "reject" &&
						outcome.unavailable.every((point) => point.outage)
					) {
						outages.push({ subject, account: `${last.reason} — ${detail}` });
						members.push(...outcome.unavailable.map(pointFailure).map(memberOf(subject)));
						continue;
					}
					if (revocation.onUnavailable === "reject") {
						options.logger?.warn(
							{ subject, reason: last.reason, detail, ...errOf(last.cause) },
							"mtls_revocation_unavailable_rejected",
						);
						return {
							ok: false,
							step: "revocation status unavailable",
							detail: `${subject}: ${last.reason} — ${detail}`,
							...withCause(last.cause),
						};
					}
					pending.push({
						event: "mtls_revocation_partially_unavailable_allowed",
						subject,
						reason: last.reason,
						detail,
						...withCause(last.cause),
					});
				}
			}

			if (outages.length > 0) {
				return {
					ok: false,
					step: "revocation status unavailable",
					detail: outages.map(({ subject, account }) => `${subject}: ${account}`).join("; "),
					cause: revocationUnavailable(
						outages.map(({ subject }) => subject),
						members,
					),
					outage: true,
				};
			}
			// The path passed: the mechanism accepted the certificate, on each
			// soft-fail and fallback it used. The request can still be refused
			// afterwards — by another mechanism, the grant, or a protected
			// resource's binding check — and these lines claim nothing about it.
			for (const line of pending) {
				options.logger?.warn(
					{ subject: line.subject, reason: line.reason, detail: line.detail, ...errOf(line.cause) },
					line.event,
				);
			}
			return { ok: true };
		},
	};
};
