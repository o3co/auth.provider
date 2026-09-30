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
 * `mode = "full-pki"`: RFC 5280 path validation with revocation. Path
 * validation is delegated to `pkijs`'s `CertificateChainValidationEngine`
 * (RFC 5280 §6, including the policy tree and name constraints), as RFC 8705
 * §7.5 advises. The narrow `mode = "pki"` (`pki.mts`) is a separate
 * synchronous walk: it can neither read that DER nor fetch.
 *
 * This module adds what the engine does not do: `pathLenConstraint` (RFC 5280
 * §4.2.1.9), the algorithm policy (§6.1.4: every certificate here, and via the
 * resolvers CRL and OCSP signatures and delegated responders), and
 * revocation. Handed no CRLs, the engine skips revocation and answers valid,
 * so a CRL endpoint that is down would look like "not revoked".
 *
 * Pass 1 validates the path with no revocation material. Pass 2 decides
 * revocation here, per certificate on the validated path (anchor excluded),
 * from material the resolvers verified against its issuer. Validating before
 * fetching is a security property: only a certificate that chains to a
 * configured anchor can cause an outbound request (`fetchGuard.mts` adds the
 * host allowlist).
 *
 * A determined `revoked` refuses under both policies. An unknown or partly
 * known status is the operator's `on-unavailable`: `"allow"` passes it and
 * logs it once the whole path has passed; `"reject"` refuses it. Under
 * `"reject"`, when every source failed as an outage (see `crl.mts`,
 * `ocspAnswer.mts`) the refusal is the server's: marked `outage`, not logged here,
 * answered 503 by core's dispatcher. A verdict anywhere on the path wins over
 * an outage, and an outage refusal names every unusable source on the path.
 *
 * `mode = "both"` asks the OCSP responder first (one small request) and the
 * CRL only when OCSP could not answer. An OCSP `unknown` is an answer: the
 * CRL is asked too but may only refuse, since it cannot list a never-issued
 * serial. A fallback to the CRL is logged once the path passes, so an OCSP
 * outage stays visible while the CRL keeps checking alive.
 */

import { X509Certificate } from "node:crypto";
import { lineSafeText, loggableError } from "@o3co/auth-provider-core";
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
 * What to do when revocation status cannot be determined. No default:
 * whether an outage that blocks logins is worse than a revoked certificate
 * still working is the operator's call, not the library's.
 */
export type OnRevocationUnavailable = "reject" | "allow";

/**
 * Where revocation status comes from. `"both"` asks the responder first and
 * falls back to the CRL when OCSP could not answer; an OCSP `unknown` is an
 * answer, which the CRL may only turn into a refusal.
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
			 * Set when the refusal is the server's outage, not a verdict: under
			 * `on-unavailable = "reject"`, only sources that did not answer
			 * usefully stopped the path. The mechanism refuses it `unavailable`
			 * (503, logged by the dispatcher) and this validator logs nothing.
			 * `cause` is then an `MtlsRevocationUnavailableError`, one member per
			 * unusable source on the path.
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
			/** CRL distribution points that could not be used, for the per-point strictness. */
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
 * A line for a certificate the mechanism accepted on the soft-fail (`"allow"`
 * with its status unknown or partly known) or on the OCSP fallback. Held until
 * the whole path has passed, then written in path order; a refused path
 * accepted nothing, and its refusal's lines are its account. The line claims
 * nothing about later refusals of the request elsewhere.
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
 * `pathLenConstraint` (RFC 5280 §4.2.1.9) bounds the CA certificates below a
 * CA. `path` is leaf-first, so below index `i` are the leaf and `i - 1`
 * intermediates. The engine does not implement it.
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
 * This package's words for the engine result codes that can occur here
 * (pkijs 3.4): path checks 8, 9, 10 and 14 (a CA check above the leaf; its
 * finer codes 3–7 never reach the result), and policy and name-constraint
 * checks 21, 41, 42, 98, 99. Revocation codes 11–13 cannot occur: no
 * revocation material is supplied. The engine's `resultMessage` is never
 * used — it is library text.
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
 * Map the engine's outcome to an audit step name, a detail in this package's
 * words, and the caught Error, if any. "No path to a trust anchor" arrives as
 * `noPath` / `noValidPath`, or as a plain Error mapped to `unknown`; the
 * latter is recognised by `noIssuer` (an empty issuer lookup observed through
 * `findIssuer`), never by the message.
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
	// The path's algorithm policy governs the revocation material about it
	// too, or a deployment refusing SHA-1 certificates would still believe
	// SHA-1 CRLs.
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
					// Under "both" the CA's CRL is the independent source a delegated
					// responder without `nocheck` is checked against. A responder
					// certificate naming no CRL is the CA specifying no method (RFC
					// 6960 §4.2.2.2.1): local policy takes the answer and logs it.
					...(crlResolver !== null
						? {
								responderRevocation: async (responder, issuer, now) => {
									const own = await byCrl(responder, issuer, now);
									if (own.kind === "unavailable") {
										return own.reason === "no_distribution_point" ? { kind: "unspecified" } : own;
									}
									// A partly usable CRL does not clear the responder: its
									// answer is discarded and the leaf falls back to its own CRL.
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
	// Responders taken without a check, so the deviation is logged once each.
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
				{ responder: lineSafeText(lookup.responder), subject: subjectOf(certificate) },
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
	 * The certificate's status from the configured source(s); see the file
	 * header for `"both"`. The certificate is unavailable only when both
	 * sources are, or when the responder said `unknown` and the CRL did not
	 * list it.
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
		// `unknown` (RFC 6960 §2.2) is an answer, not an outage, and a CRL
		// cannot list a never-issued serial, so its silence clears nothing and
		// the `unknown` stands. It can still say `revoked`, and is asked so that
		// `both` never refuses fewer certificates than `crl` alone.
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
			// A degraded answer: the failed responder is handed back as a notice,
			// written by `validate` once the whole path has passed. A certificate
			// naming no responder is a normal shape under "both" (a CA publishing
			// only CRLs for some certificates), not an outage, and has no notice.
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

			// The engine takes the **last** element of `certs` as the end entity.
			// Leaf first, it would validate the first intermediate instead and
			// skip every leaf check while reporting success — failing open and
			// quietly — so the leaf goes last and `path[0]` is asserted below.
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

			// The narrow mode's client-certificate profile (`CA:FALSE`, and
			// `clientAuth` when an EKU is present), imported rather than restated
			// so the stricter mode can never drop a check the weaker one makes.
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
			// The anchor is excluded: nothing on the path can revoke it (removing
			// it from `trusted-cas` is the mechanism there). Each certificate's
			// material must verify against the next one up. Lookups run in
			// parallel, so an outage costs the largest timeout, not their sum.
			const subjects = path.slice(0, -1);
			const outcomes = await Promise.all(
				subjects.map((certificate, index) =>
					decide(certificate, path[index + 1] as pkijs.Certificate, now),
				),
			);
			// Under "reject", an outage is held until every certificate has been
			// judged: a revocation, or an unavailability that is not an outage, is
			// a verdict a retry would not change, and it wins. Otherwise the
			// outage is returned for the whole path, every unusable source in
			// path order.
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

				// A determined revocation settles the certificate under both
				// policies, before any gap is judged; refusing it as unavailable
				// would report an outage where there was a revocation.
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
							{
								subject,
								reason: outcome.reason,
								detail: lineSafeText(outcome.detail),
								...errOf(outcome.cause),
							},
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

				// A certificate absent from every CRL obtained, with some points
				// unusable, has a partial answer. "reject" refuses it: one CRL cannot
				// show the CA's other points were redundant, and an undeclared
				// partition looks exactly like this. "allow" passes it, logged under
				// its own message: "checked against part of its revocation material"
				// and "not checked at all" differ on an operator's dashboard.
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
							{ subject, reason: last.reason, detail: lineSafeText(detail), ...errOf(last.cause) },
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
					{
						subject: line.subject,
						reason: line.reason,
						detail: lineSafeText(line.detail),
						...errOf(line.cause),
					},
					line.event,
				);
			}
			return { ok: true };
		},
	};
};
