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
 * the configuration says: `"reject"` refuses on the first certificate whose
 * status is unknown — or only partly known, because one of the distribution
 * points it names could not be used (#446) — `"allow"` skips exactly those
 * certificates and logs each one, and a status that *was* determined as
 * revoked is refused under both.
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
 * when a responder was actually asked and failed, so an OCSP outage is
 * visible even while the CRL keeps revocation checking alive.
 */

import { X509Certificate } from "node:crypto";
import { loggableError } from "@o3co/auth-provider-core";
import * as pkijs from "pkijs";
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
	  }
	| {
			readonly kind: "unavailable";
			readonly reason: string;
			readonly detail: string;
			/** The library error behind `reason`, when one threw. */
			readonly cause?: unknown;
	  };

/** `{ cause }` when there is one, for a spread into an outcome or a result. */
const withCause = (cause: unknown): { cause?: unknown } => (cause !== undefined ? { cause } : {});

/** `{ err }`, the projection of `cause`, when there is one — for a log line. */
const errOf = (cause: unknown): { err?: ReturnType<typeof loggableError> } =>
	cause !== undefined ? { err: loggableError(cause) } : {};

const toPkijs = (certificate: X509Certificate): pkijs.Certificate =>
	pkijs.Certificate.fromBER(certificate.raw);

const toNode = (certificate: pkijs.Certificate): X509Certificate =>
	new X509Certificate(Buffer.from(certificate.toSchema(true).toBER(false)));

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
 * This package's words for the result codes the engine can answer with here:
 * pkijs's own checks (`resultCode` 3–10, 21, 41, 42, 98, 99). The engine runs
 * without revocation material, so its revocation codes (11–13) cannot occur;
 * revocation outcomes are named by the local pass below. The engine's
 * `resultMessage` is never used — it is the library's text, and for an
 * error it caught, that error's message.
 */
const ENGINE_FAILURE_DETAIL: Readonly<Record<number, string>> = {
	3: "a CA certificate on the path asserts keyCertSign without basicConstraints",
	4: "a CA certificate on the path lacks the keyCertSign key usage",
	5: "an intermediate certificate lacks the cRLSign key usage",
	6: "a critical extension on the path could not be parsed",
	7: "the chain holds more than one end-entity certificate",
	8: "a certificate on the path is not yet valid or has expired",
	9: "the path is too short",
	10: "issuer and subject names on the path do not chain",
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
		noIssuer ||
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
			};
		}
		// Every CRL here verified against `issuer`, whose subject is this
		// certificate's issuer name, so the serial comparison is the whole
		// check.
		if (lookup.crls.some((crl) => crl.isCertificateRevoked(certificate))) {
			return {
				kind: "revoked",
				detail:
					`${toNode(certificate).subject}: listed on the CRL published by ` +
					toNode(issuer).subject,
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
			};
		}
		if (lookup.responderUnchecked && !uncheckedResponders.has(lookup.responder)) {
			uncheckedResponders.add(lookup.responder);
			options.logger?.warn(
				{ responder: lookup.responder, subject: toNode(certificate).subject },
				"mtls_ocsp_responder_unchecked",
			);
		}
		if (lookup.status.status === "revoked") {
			const reason = lookup.status.reason === undefined ? "" : ` (${lookup.status.reason})`;
			return {
				kind: "revoked",
				detail:
					`${toNode(certificate).subject}: reported revoked at ` +
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
		// A certificate that names no responder is a normal shape under
		// "both" — a CA that publishes only CRLs for some of its
		// certificates — not an outage. A responder that was asked and did
		// not answer is, and stays visible even while the CRL carries on.
		if (ocsp.reason !== "no_responder") {
			options.logger?.warn(
				{
					subject: toNode(certificate).subject,
					reason: ocsp.reason,
					detail: ocsp.detail,
					...errOf(ocsp.cause),
				},
				"mtls_revocation_ocsp_fallback",
			);
		}
		const crl = await byCrl(certificate, issuer, now);
		if (crl.kind !== "unavailable") return crl;
		// `err` goes with `reason`, and both are the CRL's: the OCSP failure's
		// projection was on the fallback line above.
		return {
			kind: "unavailable",
			reason: crl.reason,
			detail: `ocsp: ${ocsp.reason} (${ocsp.detail}); crl: ${crl.reason} (${crl.detail})`,
			...withCause(crl.cause),
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
					const subject = toNode(certificate).subject;
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
					// configuration.
					options.logger?.warn(
						{ subject, reason: outcome.reason, detail: outcome.detail, ...errOf(outcome.cause) },
						"mtls_revocation_unavailable_allowed",
					);
					continue;
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
				// — under its own message, because "checked against part of its
				// revocation material" and "not checked at all" are different
				// facts on an operator's dashboard.
				if (outcome.unavailable.length > 0) {
					const subject = toNode(certificate).subject;
					const last = outcome.unavailable[outcome.unavailable.length - 1] as CrlPointUnavailable;
					const detail = describeUnavailable(outcome.unavailable);
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
					options.logger?.warn(
						{ subject, reason: last.reason, detail, ...errOf(last.cause) },
						"mtls_revocation_partially_unavailable_allowed",
					);
				}
			}

			return { ok: true };
		},
	};
};
