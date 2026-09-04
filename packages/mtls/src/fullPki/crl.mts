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
 * CRL retrieval, freshness and caching for `mode = "full-pki"`.
 *
 * `pkijs` is given CRLs; it does not go and get them. Everything between
 * "this certificate names a distribution point" and "here is a CRL this
 * issuer actually published" lives here: reading the extension, fetching
 * under the guards in `fetchGuard.mts`, parsing, **verifying the signature
 * against the issuing CA**, judging freshness, and caching so a busy token
 * endpoint does not re-fetch per request.
 *
 * ### Why the signature is checked here and not left to the engine
 *
 * The engine does verify a CRL's signature — but only when it is finally
 * consulted, which is after this module has already decided whether to cache
 * the bytes. A CRL that is cached first and verified later is a forged CRL
 * that stays in memory for up to `cache-ttl-seconds`: one injected response
 * over the plain-http transport most distribution points use would refuse
 * every client of that distribution point until the entry expired. So
 * nothing is stored, and nothing is returned, until the signature verifies
 * against the key of the certificate's issuer and that issuer's `keyUsage`
 * (when present) includes `cRLSign` (RFC 5280 §6.3.3). A failure is its own
 * outcome, `bad_signature`, and is deliberately never cached in either
 * direction: it must not pin a refusal, and it must not pin an acceptance.
 *
 * ### One fetch per distribution point, not one per request
 *
 * A cache miss on a busy token endpoint is many requests missing at once,
 * and an outage is a miss on every request for as long as it lasts. Two
 * bounds keep that from becoming one guarded fetch per request, each holding
 * a connection for up to `fetch-timeout-ms`:
 *
 *  - concurrent lookups of the same URL share one in-flight fetch;
 *  - a URL that could not be used — unreachable, unparseable, serving a CRL
 *    that is stale or undated, or serving one this resolver does not process
 *    (an unsupported critical extension, a delta, a scoped CRL, a signature
 *    algorithm outside the policy) — is remembered as unavailable for
 *    `CRL_NEGATIVE_CACHE_TTL_MS`, so a stuck endpoint costs one probe per
 *    window rather than one per request. `bad_signature` is exempt, per the
 *    section above.
 *
 * The last group is why a CRL's extensions are inspected *before* its
 * signature (#447). pkijs's `verify` answers `false` for a critical extension
 * outside its own list — indistinguishable from a forged signature — and
 * `bad_signature` is never remembered, so a CA publishing such a CRL cost one
 * guarded fetch per request under both policies, with the window unable to
 * help. Inspecting first gives the outcome its own name. Remembering it on
 * bytes that have not been verified is safe for the same reason remembering
 * `unparseable` is: the decision depends only on the bytes' structure, and it
 * is only ever a decision *not* to use the CRL. Nothing an attacker injects
 * can pin an acceptance this way, and a pinned refusal is bounded by the
 * window exactly as an injected 503 already is.
 *
 * ### The algorithm policy applies to the CRL too (#470)
 *
 * `validate.mts` refuses a certificate signed with an algorithm outside
 * `signature-algorithms`; pkijs, asked to verify a CRL, accepts
 * `sha1WithRSAEncryption` and `ecdsa-with-SHA1` as readily as it accepts a
 * certificate's, so a SHA-1-signed CRL was believed about a certificate that
 * a SHA-1 signature would have refused. The CRL's `signatureAlgorithm` — the
 * field pkijs verifies with — is checked against the same policy, before the
 * signature itself, and the outcome is `algorithm_not_permitted`. It is
 * remembered for the negative window like `unsupported_critical_extension`,
 * not exempted like `bad_signature`: the decision is on the OID the bytes
 * name, not on whether they verify, so an injected response can pin at most
 * a bounded refusal, which an injected 503 already can; and the algorithm is
 * a property of the CA's own material, identical on every fetch until the
 * CA changes it, so not remembering it would cost one guarded fetch per
 * request under both policies — the pattern #447 closed. The issuer's key
 * size is not re-checked here: the issuer is on the validated path, and the
 * path pass has already held it to `min-rsa-key-bits`.
 *
 * ### What a CRL may say about its own scope
 *
 * RFC 5280 lets a CA split its revocation information: by reason code across
 * several distribution points (`reasons` on the point, `onlySomeReasons` on
 * the CRL), by certificate type or by distribution point
 * (`issuingDistributionPoint`), into a base CRL plus deltas
 * (`deltaCRLIndicator`), or by delegating publication to another issuer
 * (`cRLIssuer`, `indirectCRL`). pkijs accepts every one of those extensions
 * as well-known and then ignores them — `isCertificateRevoked` compares
 * serial numbers — so a CRL saying "user certificates only" or "changes since
 * base 41" would be read as the complete list for any certificate at all.
 * None of them is implemented here. Each is *recognised* and reported as
 * unsupported, so that `on-unavailable` applies, rather than half-honoured
 * (#446). A `freshestCRL` pointer is the one exception: the base CRL that
 * carries it is complete as of its own `thisUpdate`, so it is used as such
 * and the delta it points to is simply not fetched.
 *
 * An unsupported *distribution point* is skipped, not fatal. A point without
 * `reasons` covers every reason code (§4.2.1.13), so a plain HTTP point
 * beside a partitioned or indirect one is a complete answer by itself; the
 * unsupported point is reported alongside the CRLs the usable points
 * yielded, exactly as a point that was down is, and the caller's policy
 * decides whether the gap matters. Only a certificate with no usable point
 * left is unavailable for it (#469).
 *
 * ### The failure that matters
 *
 * `pkijs` skips its revocation block entirely when it is handed no CRLs. So
 * "the CRL server was down" and "the certificate is not revoked" arrive at
 * the engine as the same input and produce the same verdict: valid. Whether
 * that is acceptable is an operator's decision about their threat model, not
 * something a library gets to make silently — so this module reports
 * unavailability as its own outcome, and the caller applies the configured
 * `on-unavailable` policy to each certificate on the path itself; the engine
 * is never handed revocation material at all. A certificate may also name
 * several distribution points; the lookup reports the ones it could not use
 * alongside the CRLs it did obtain, and leaves it to the caller whether a
 * partial answer is an answer — under `"reject"` it is not.
 */

import { createHash } from "node:crypto";
import * as pkijs from "pkijs";
import { type AlgorithmPolicy, checkSignatureAlgorithm } from "./algorithms.mjs";
import { checkCrlCriticalExtensions, extensionValueParsed } from "./criticalExtensions.mjs";
import type { GuardedFetch } from "./fetchGuard.mjs";

/** OID of the `cRLDistributionPoints` extension (RFC 5280 §4.2.1.13). */
const OID_CRL_DISTRIBUTION_POINTS = "2.5.29.31";

/** OID of `keyUsage` (RFC 5280 §4.2.1.3). */
const OID_KEY_USAGE = "2.5.29.15";

/** OID of `deltaCRLIndicator` (RFC 5280 §5.2.4). */
const OID_DELTA_CRL_INDICATOR = "2.5.29.27";

/** OID of `issuingDistributionPoint` (RFC 5280 §5.2.5). */
const OID_ISSUING_DISTRIBUTION_POINT = "2.5.29.28";

/** `cRLSign` bit of `keyUsage`, MSB-first within the first octet. */
const KEY_USAGE_CRL_SIGN = 0x02;

/** `GeneralName` tag for `uniformResourceIdentifier`. */
const GENERAL_NAME_URI = 6;

/**
 * Why a certificate's revocation status could not be determined. Values are
 * stable — audit logs read them.
 *
 * The `unsupported_*` reasons are shapes RFC 5280 permits and this resolver
 * recognises but does not implement: a distribution point that partitions by
 * reason or names another issuer, a delta or scoped CRL, a critical extension
 * nothing here processes. Each is reported rather than read as authoritative
 * (#446, #447). `algorithm_not_permitted` is a CRL signed with an algorithm
 * outside `oauth.mtls.full-pki.signature-algorithms` — the same policy the
 * path is held to (#470).
 */
export type CrlUnavailableReason =
	| "no_distribution_point"
	| "unsupported_distribution_point"
	| "fetch_failed"
	| "unparseable"
	| "unsupported_critical_extension"
	| "unsupported_crl_scope"
	| "algorithm_not_permitted"
	| "no_next_update"
	| "stale"
	| "bad_signature";

/**
 * One distribution point that yielded no usable CRL, and why: a URI that was
 * tried and failed, or a point of a shape this resolver does not implement,
 * named by its first URI and never tried (#469).
 */
export interface CrlPointUnavailable {
	readonly url: string;
	readonly reason: CrlUnavailableReason;
	readonly detail: string;
}

export type CrlLookup =
	| {
			readonly ok: true;
			readonly crls: readonly pkijs.CertificateRevocationList[];
			/**
			 * Distribution points that yielded no CRL — one entry per URI tried,
			 * and one per unsupported point that was not — empty when every
			 * point the certificate names was used. A lookup can be `ok` and
			 * incomplete at once; whether that is an answer is the caller's
			 * `on-unavailable` decision, not this module's (#446, #469).
			 */
			readonly unavailable: readonly CrlPointUnavailable[];
	  }
	| { readonly ok: false; readonly reason: CrlUnavailableReason; readonly detail: string };

/** One audit-trail line per URI that could not be used. */
export const describeUnavailable = (points: readonly CrlPointUnavailable[]): string =>
	points.map((point) => `${point.url}: ${point.reason} (${point.detail})`).join("; ");

/**
 * How long a distribution point that could not be used is remembered as
 * unavailable, in milliseconds.
 *
 * Not a configuration knob, deliberately. The window exists to absorb a
 * burst — a cache expiry or an outage must not turn into one fetch per
 * request, each waiting up to `fetch-timeout-ms` on the token endpoint's
 * critical path — not to remember the outage: a CA that comes back must be
 * noticed in seconds, not in the hours `cache-ttl-seconds` is measured in.
 */
export const CRL_NEGATIVE_CACHE_TTL_MS = 30_000;

export type CrlDistributionPoints =
	| {
			readonly ok: true;
			/** One entry per usable distribution point: that point's HTTP(S) URIs, in order. */
			readonly points: readonly (readonly string[])[];
			/**
			 * Distribution points of a shape this resolver does not implement —
			 * carrying `reasons` or `cRLIssuer` — one entry per point, never
			 * fetched. Reported beside the usable points so the caller can
			 * count them as gaps under `"reject"` (#469).
			 */
			readonly unsupported: readonly CrlPointUnavailable[];
	  }
	| {
			readonly ok: false;
			readonly reason: "no_distribution_point" | "unsupported_distribution_point";
			readonly detail: string;
	  };

const isHttpUrl = (value: string): boolean => /^https?:\/\//i.test(value);

/** The absolute HTTP(S) URIs a distribution point is named by, in order. */
const httpUrls = (point: pkijs.DistributionPoint): readonly string[] => {
	const name = point.distributionPoint;
	if (!Array.isArray(name)) return [];
	return name
		.filter((generalName) => generalName.type === GENERAL_NAME_URI)
		.map((generalName) => generalName.value)
		.filter((value): value is string => typeof value === "string" && isHttpUrl(value));
};

/**
 * Why a distribution point is one this resolver does not implement. With
 * `reasons`, no single CRL is the complete answer and the reasons-mask
 * bookkeeping of RFC 5280 §6.3.3 is not implemented; with `cRLIssuer`, the
 * CRL is signed by someone other than the certificate's issuer, and the
 * signature here is verified against the issuer only. Either read as complete
 * would be a partial or foreign list standing in for the whole (#446).
 */
const unsupportedPointDetail = (point: pkijs.DistributionPoint): string | null => {
	if (point.reasons !== undefined) {
		return (
			"a distribution point carries reasons: the CA partitions revocation by reason " +
			"code across several CRLs, which this validator does not support"
		);
	}
	if (point.cRLIssuer !== undefined) {
		return (
			"a distribution point names a cRLIssuer: its CRL is published by someone other " +
			"than the certificate's issuer (an indirect CRL), which this validator does not support"
		);
	}
	return null;
};

/**
 * Read the distribution points a certificate advertises, one URI list per
 * usable point, plus the points this resolver does not implement.
 *
 * The shape is kept rather than flattened because it carries meaning:
 * several names within one point are alternative ways to obtain the *same*
 * CRL (RFC 5280 §4.2.1.13), while separate points are not known to be. The
 * resolver tries a point's names until one answers, and reports a point none
 * of whose names did.
 *
 * Only absolute HTTP(S) URIs are kept. A point with none — an LDAP URI, a
 * directory name, a name relative to the issuer — is one this resolver
 * cannot consult at all, so it is left out rather than counted as failed: a
 * directory-backed CA that lists an LDAP point beside an HTTP one must not
 * become unavailable under `"reject"` for it. A certificate left with no
 * point is `no_distribution_point`, an honest "cannot check" rather than a
 * silent pass.
 *
 * A point carrying `reasons` or `cRLIssuer` is skipped, never fetched, and
 * reported as `unsupported_distribution_point` — beside the usable points,
 * not instead of them. A point *without* `reasons` covers every reason code
 * (§4.2.1.13), so a plain point beside a partitioned or indirect one is a
 * complete answer on its own; giving up on the whole extension at the first
 * unsupported point discarded that answer, and read a revoked certificate
 * as merely "unavailable" (#469). Whether the skipped point is a gap is the
 * caller's `on-unavailable` decision. Only a certificate left with no usable
 * point is `unsupported_distribution_point` as a whole. The point is named
 * by its first HTTP(S) URI in the audit line; one with no such URI is still
 * reported, since the shape, not the transport, is what is unsupported.
 */
export const crlDistributionPoints = (certificate: pkijs.Certificate): CrlDistributionPoints => {
	const extension = certificate.extensions?.find(
		(ext) => ext.extnID === OID_CRL_DISTRIBUTION_POINTS,
	);
	const parsed = extension?.parsedValue as pkijs.CRLDistributionPoints | undefined;
	const points: (readonly string[])[] = [];
	const unsupported: CrlPointUnavailable[] = [];
	for (const point of parsed?.distributionPoints ?? []) {
		const urls = httpUrls(point);
		const detail = unsupportedPointDetail(point);
		if (detail !== null) {
			unsupported.push({
				url: urls[0] ?? "(distribution point with no HTTP(S) URI)",
				reason: "unsupported_distribution_point",
				detail,
			});
			continue;
		}
		if (urls.length > 0) points.push(urls);
	}
	if (points.length === 0) {
		if (unsupported.length > 0) {
			return {
				ok: false,
				reason: "unsupported_distribution_point",
				detail: describeUnavailable(unsupported),
			};
		}
		return {
			ok: false,
			reason: "no_distribution_point",
			detail: "certificate advertises no cRLDistributionPoints HTTP(S) URI",
		};
	}
	return { ok: true, points, unsupported };
};

/** Reasons that are remembered for the negative window. */
type RememberedReason = Exclude<
	CrlUnavailableReason,
	"no_distribution_point" | "unsupported_distribution_point" | "bad_signature"
>;

type CacheEntry =
	| {
			readonly kind: "crl";
			readonly crl: pkijs.CertificateRevocationList;
			/** Epoch millis after which this entry must be re-fetched. */
			readonly expiresAt: number;
	  }
	| {
			readonly kind: "unavailable";
			readonly reason: RememberedReason;
			readonly detail: string;
			/** Epoch millis after which the distribution point is tried again. */
			readonly expiresAt: number;
	  };

/** What fetching and parsing one distribution point produced, before any verification. */
type Loaded =
	| { readonly ok: true; readonly crl: pkijs.CertificateRevocationList }
	| {
			readonly ok: false;
			readonly reason: "fetch_failed" | "unparseable";
			readonly detail: string;
	  };

/** What one distribution-point URI produced, after every check. */
type UrlOutcome =
	| { readonly ok: true; readonly crl: pkijs.CertificateRevocationList }
	| { readonly ok: false; readonly reason: CrlUnavailableReason; readonly detail: string };

export interface CrlResolverOptions {
	readonly fetch: GuardedFetch;
	/**
	 * Upper bound on how long a CRL is reused, in seconds. The CRL's own
	 * `nextUpdate` still wins when it is sooner — this only stops a CA that
	 * publishes a year-long `nextUpdate` from pinning a stale answer in memory
	 * for a year.
	 */
	readonly cacheTtlSeconds: number;
	/**
	 * The signature-algorithm policy the validated path is held to, applied
	 * to each CRL's signature as well (#470). See the module header.
	 */
	readonly algorithms: AlgorithmPolicy;
	/** Bound on cache size, so a large trust set cannot grow it without limit. */
	readonly maxCacheEntries?: number;
}

export interface CrlResolver {
	/**
	 * Fetch (or reuse) the CRLs covering `certificate` — one per distribution
	 * point it names — verified against `issuer`, the certificate that issued
	 * it, i.e. the next element up the validated path. Only a CRL whose
	 * signature verifies against `issuer`'s key is ever returned or cached.
	 * Concurrent calls for the same distribution point share one fetch, and a
	 * distribution point that could not be used is not retried within
	 * `CRL_NEGATIVE_CACHE_TTL_MS`.
	 */
	resolve(certificate: pkijs.Certificate, issuer: pkijs.Certificate, now: Date): Promise<CrlLookup>;
	/** Entry count, usable and remembered-unavailable alike — for tests and for a future metric. */
	size(): number;
}

const DEFAULT_MAX_CACHE_ENTRIES = 256;

/**
 * Whether `issuer` is entitled to sign CRLs at all: RFC 5280 §6.3.3 (f) — its
 * `keyUsage`, when present, MUST include `cRLSign`. Being entitled to sign
 * certificates is not being entitled to publish revocation lists, and the
 * bit is the CA's own statement about which of the two this key does.
 * Absence is unconstrained, as for every other `keyUsage` check in this arm.
 */
const issuerMaySignCrls = (issuer: pkijs.Certificate): boolean => {
	const extension = issuer.extensions?.find((ext) => ext.extnID === OID_KEY_USAGE);
	if (extension === undefined) return true;
	const parsed = extension.parsedValue as
		| { valueBlock?: { valueHexView?: Uint8Array } }
		| undefined;
	const bytes = parsed?.valueBlock?.valueHexView;
	// Present but unreadable is a restriction that cannot be honoured, not an
	// absent one — the same distinction `checkLeafKeyUsage` draws.
	if (bytes === undefined || bytes.length === 0) return false;
	return ((bytes[0] ?? 0) & KEY_USAGE_CRL_SIGN) === KEY_USAGE_CRL_SIGN;
};

/**
 * Verify that `issuer` published `crl`. `verify` also answers `false` when
 * the CRL's issuer name is not `issuer`'s subject — "not a CRL this issuer
 * published", which is the question being asked. It would answer `false` for
 * a critical extension outside its own list too, but none reaches it:
 * `checkCrlCriticalExtensions` runs first and passes only OIDs on that list.
 */
const verifySignature = async (
	crl: pkijs.CertificateRevocationList,
	issuer: pkijs.Certificate,
): Promise<{ ok: true } | { ok: false; detail: string }> => {
	if (!issuerMaySignCrls(issuer)) {
		return { ok: false, detail: "the issuing CA's keyUsage omits cRLSign (RFC 5280 §6.3.3)" };
	}
	let verified: boolean;
	try {
		verified = await crl.verify({ issuerCertificate: issuer });
	} catch (err) {
		return {
			ok: false,
			detail: `signature check failed: ${err instanceof Error ? err.message : String(err)}`,
		};
	}
	return verified
		? { ok: true }
		: { ok: false, detail: "signature does not verify against the issuing CA" };
};

/**
 * Whether the CRL claims a scope this resolver can honour.
 *
 * RFC 5280 §6.3.3 (b) has a validator match a CRL's
 * `issuingDistributionPoint` against the certificate and the point it was
 * fetched from, and (c) combine a delta with its base. Neither is
 * implemented. A CRL stating a scope narrower than "everything this issuer
 * issued" is reported as unsupported rather than read as complete, and so is
 * a delta, which by definition lists only the changes since a base this
 * resolver has not fetched. pkijs accepts both extensions as well-known and
 * then ignores them, so without this check a CRL saying "user certificates
 * only" was authoritative for an intermediate (#446).
 *
 * Neither extension is looked up by criticality: both MUST be critical per
 * the RFC, but a CA that marks one non-critical has still scoped its CRL.
 */
const checkScope = (
	crl: pkijs.CertificateRevocationList,
): { ok: true } | { ok: false; detail: string } => {
	const extensions = crl.crlExtensions?.extensions ?? [];
	if (extensions.some((ext) => ext.extnID === OID_DELTA_CRL_INDICATOR)) {
		return {
			ok: false,
			detail:
				"a delta CRL (deltaCRLIndicator): it lists only the changes since a base CRL, " +
				"and delta CRLs are not supported",
		};
	}
	const idp = extensions.find((ext) => ext.extnID === OID_ISSUING_DISTRIBUTION_POINT);
	if (idp === undefined) return { ok: true };
	const parsed: unknown = idp.parsedValue;
	if (!(parsed instanceof pkijs.IssuingDistributionPoint) || !extensionValueParsed(idp)) {
		return {
			ok: false,
			detail: "its issuingDistributionPoint could not be parsed, so the scope it states is unknown",
		};
	}
	const restrictions = [
		parsed.distributionPoint !== undefined ? "distributionPoint" : null,
		parsed.onlyContainsUserCerts ? "onlyContainsUserCerts" : null,
		parsed.onlyContainsCACerts ? "onlyContainsCACerts" : null,
		parsed.onlySomeReasons !== undefined ? "onlySomeReasons" : null,
		parsed.indirectCRL ? "indirectCRL" : null,
		parsed.onlyContainsAttributeCerts ? "onlyContainsAttributeCerts" : null,
	].filter((field): field is string => field !== null);
	if (restrictions.length === 0) return { ok: true };
	return {
		ok: false,
		detail:
			`its issuingDistributionPoint scopes it (${restrictions.join(", ")}); partitioned ` +
			"and indirect CRLs are not supported",
	};
};

/**
 * A cache entry is keyed by the distribution point *and* the key the CRL was
 * verified against. Two CAs can share a subject name — a key rollover keeps
 * the DN — and a CRL accepted for one must never be handed to a certificate
 * the other issued.
 */
const issuerKeyId = (issuer: pkijs.Certificate): string =>
	createHash("sha256")
		.update(new Uint8Array(issuer.subjectPublicKeyInfo.toSchema().toBER(false)))
		.digest("hex");

const usableKey = (url: string, issuerId: string): string => `crl:${url}\n${issuerId}`;

/**
 * Unavailability is a property of the distribution point, not of who asked,
 * so it is remembered per URL.
 */
const unavailableKey = (url: string): string => `down:${url}`;

export const createCrlResolver = (options: CrlResolverOptions): CrlResolver => {
	const cache = new Map<string, CacheEntry>();
	const maxEntries = options.maxCacheEntries ?? DEFAULT_MAX_CACHE_ENTRIES;
	/** Fetches in progress, so concurrent misses on one URL issue one request. */
	const inFlight = new Map<string, Promise<Loaded>>();

	/**
	 * A CRL with no `nextUpdate` is treated as unusable rather than as
	 * eternally fresh. RFC 5280 §5.1.2.5 requires conforming CAs to include
	 * it, and without it there is no way to tell a current CRL from one
	 * captured years ago and replayed — which is exactly the position an
	 * attacker who has had a certificate revoked wants us in.
	 */
	const freshness = (
		crl: pkijs.CertificateRevocationList,
		now: Date,
	):
		| { ok: true; expiresAt: number }
		| { ok: false; reason: "no_next_update" | "stale"; detail: string } => {
		const nextUpdate = crl.nextUpdate?.value;
		if (nextUpdate === undefined) {
			return {
				ok: false,
				reason: "no_next_update",
				detail: "the CRL carries no nextUpdate (RFC 5280 §5.1.2.5)",
			};
		}
		if (nextUpdate.getTime() <= now.getTime()) {
			return {
				ok: false,
				reason: "stale",
				detail: `the CRL's nextUpdate ${nextUpdate.toISOString()} has passed`,
			};
		}
		return {
			ok: true,
			expiresAt: Math.min(nextUpdate.getTime(), now.getTime() + options.cacheTtlSeconds * 1000),
		};
	};

	const store = (key: string, entry: CacheEntry): void => {
		if (cache.size >= maxEntries && !cache.has(key)) {
			// Oldest insertion first — Map preserves insertion order. A CRL cache
			// has no hot/cold distinction worth a real eviction policy; the bound
			// exists so the map cannot grow without limit, not to maximise hits.
			const oldest = cache.keys().next();
			if (!oldest.done) cache.delete(oldest.value);
		}
		cache.set(key, entry);
	};

	const remember = (url: string, reason: RememberedReason, detail: string, now: Date): void =>
		store(unavailableKey(url), {
			kind: "unavailable",
			reason,
			detail,
			expiresAt: now.getTime() + CRL_NEGATIVE_CACHE_TTL_MS,
		});

	const fetchAndParse = async (url: string): Promise<Loaded> => {
		const fetched = await options.fetch(url);
		if (!fetched.ok) {
			return { ok: false, reason: "fetch_failed", detail: `${fetched.reason} (${fetched.detail})` };
		}
		try {
			return { ok: true, crl: pkijs.CertificateRevocationList.fromBER(fetched.bytes) };
		} catch (err) {
			return {
				ok: false,
				reason: "unparseable",
				detail: `not a DER CRL (${err instanceof Error ? err.message : String(err)})`,
			};
		}
	};

	/** Fetch `url`, joining a fetch of it that is already in progress. */
	const load = (url: string): Promise<Loaded> => {
		const existing = inFlight.get(url);
		if (existing !== undefined) return existing;
		const pending = fetchAndParse(url).finally(() => inFlight.delete(url));
		inFlight.set(url, pending);
		return pending;
	};

	/** What `url` yields for a certificate `issuer` issued — from the cache, or by fetching now. */
	const lookup = async (
		url: string,
		issuer: pkijs.Certificate,
		issuerId: string,
		now: Date,
	): Promise<UrlOutcome> => {
		const usable = cache.get(usableKey(url, issuerId));
		if (usable?.kind === "crl" && usable.expiresAt > now.getTime()) {
			return { ok: true, crl: usable.crl };
		}
		const unavailable = cache.get(unavailableKey(url));
		if (unavailable?.kind === "unavailable" && unavailable.expiresAt > now.getTime()) {
			return {
				ok: false,
				reason: unavailable.reason,
				detail: `${unavailable.detail}; not retried yet`,
			};
		}

		const loaded = await load(url);
		if (!loaded.ok) {
			remember(url, loaded.reason, loaded.detail, now);
			return loaded;
		}

		// Extensions before the signature, so that a CRL this resolver cannot
		// use is named as such and remembered — see the module header (#447).
		// Nothing the CRL *says* is acted on here, only what it is shaped
		// like, and the answer is at most "do not use it".
		const critical = checkCrlCriticalExtensions(loaded.crl);
		if (!critical.ok) {
			remember(url, "unsupported_critical_extension", critical.detail, now);
			return { ok: false, reason: "unsupported_critical_extension", detail: critical.detail };
		}
		const scope = checkScope(loaded.crl);
		if (!scope.ok) {
			remember(url, "unsupported_crl_scope", scope.detail, now);
			return { ok: false, reason: "unsupported_crl_scope", detail: scope.detail };
		}

		// The signature *algorithm* before the signature, for the same reason
		// the extensions are: this is a decision on the OID the CRL names,
		// not on whether it verifies, and the answer is only ever "do not
		// use it" — so it is safe to remember on unverified bytes, and it
		// is remembered, or a CA that signs with SHA-1 would cost one
		// guarded fetch per request (see the module header, #470).
		// `signatureAlgorithm` is the field pkijs verifies with; RFC 5280
		// §5.1.1.2 requires the tbsCertList copy to match it.
		const algorithm = checkSignatureAlgorithm(
			loaded.crl.signatureAlgorithm.algorithmId,
			options.algorithms,
		);
		if (!algorithm.ok) {
			const detail = `the CRL's signature algorithm ${algorithm.detail}`;
			remember(url, "algorithm_not_permitted", detail, now);
			return { ok: false, reason: "algorithm_not_permitted", detail };
		}

		// Nothing an unverified CRL says is acted on — not even its dates — so
		// the signature comes before freshness, and a failure here is the one
		// outcome that is never remembered: a single injected response must
		// not pin a refusal for anyone.
		const signature = await verifySignature(loaded.crl, issuer);
		if (!signature.ok) {
			return { ok: false, reason: "bad_signature", detail: signature.detail };
		}

		const fresh = freshness(loaded.crl, now);
		if (!fresh.ok) {
			// Not stored as usable. The failure is remembered for the negative
			// window only, so a responder that has stopped publishing costs one
			// probe per window rather than one per request — and is noticed
			// within seconds once it publishes again.
			remember(url, fresh.reason, fresh.detail, now);
			return { ok: false, reason: fresh.reason, detail: fresh.detail };
		}

		store(usableKey(url, issuerId), {
			kind: "crl",
			crl: loaded.crl,
			expiresAt: fresh.expiresAt,
		});
		return { ok: true, crl: loaded.crl };
	};

	return {
		size: () => cache.size,

		resolve: async (certificate, issuer, now) => {
			const points = crlDistributionPoints(certificate);
			if (!points.ok) return points;

			const issuerId = issuerKeyId(issuer);
			const crls: pkijs.CertificateRevocationList[] = [];
			// A point of a shape this resolver does not implement is a point
			// that yielded no CRL, reported with the rest — nothing about it
			// is fetched, and the usable points are still consulted (#469).
			const unavailable: CrlPointUnavailable[] = [...points.unsupported];

			for (const urls of points.points) {
				// Within one point the names are alternatives (RFC 5280
				// §4.2.1.13): the first that yields a CRL answers for the point
				// and the rest are not fetched. A point none of whose names
				// yields one is reported with every name's failure, and the
				// next point is still tried — the caller sees the whole
				// picture, and decides.
				const failures: CrlPointUnavailable[] = [];
				let found: pkijs.CertificateRevocationList | undefined;
				for (const url of urls) {
					const outcome = await lookup(url, issuer, issuerId, now);
					if (outcome.ok) {
						found = outcome.crl;
						break;
					}
					failures.push({ url, reason: outcome.reason, detail: outcome.detail });
				}
				if (found === undefined) unavailable.push(...failures);
				else crls.push(found);
			}

			if (crls.length === 0) {
				const last = unavailable[unavailable.length - 1];
				return {
					ok: false,
					reason: last?.reason ?? "fetch_failed",
					detail: describeUnavailable(unavailable),
				};
			}
			return { ok: true, crls, unavailable };
		},
	};
};
