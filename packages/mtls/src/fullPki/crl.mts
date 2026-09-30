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
 * CRL retrieval, verification, freshness and caching for `mode = "full-pki"`.
 * `pkijs` is only handed CRLs; fetching (under `fetchGuard.mts`), parsing,
 * checking and caching happen here. The engine is never given revocation
 * material: it reads "no CRLs" as "not revoked", so unavailability is its own
 * outcome and the caller applies `on-unavailable` to each certificate.
 *
 * Checks on a fetched CRL, in order:
 * 1. Critical extensions, scope and signature algorithm. These judge only the
 *    bytes' structure and can only refuse, so they are safe to remember on
 *    unverified bytes (a pinned refusal is bounded like an injected 503).
 *    They precede the signature because pkijs's `verify` answers `false` for
 *    an unknown critical extension, indistinguishable from a forgery.
 * 2. The signature, against the issuer's key; the issuer's `keyUsage`, when
 *    present, must include `cRLSign` (RFC 5280 §6.3.3). Nothing is cached or
 *    returned before it verifies: one forged CRL injected over plain http
 *    would otherwise refuse every client until the entry expired.
 *    `bad_signature` is never cached, so it pins neither refusal nor
 *    acceptance.
 * 3. Freshness (`nextUpdate`).
 *
 * Concurrent lookups of one URL share a fetch, and an unusable URL (except
 * `bad_signature`) is remembered for `CRL_NEGATIVE_CACHE_TTL_MS`, so an outage
 * costs one probe per window rather than one guarded fetch per request.
 *
 * Partitioned, delta and indirect CRLs (`reasons`, `cRLIssuer`,
 * `issuingDistributionPoint`, `deltaCRLIndicator`) are not implemented. pkijs
 * accepts those extensions and then ignores them, reading a partial list as
 * complete, so each is recognised and reported as unsupported. An unsupported
 * distribution point is skipped, not fatal: a point without `reasons` covers
 * every reason code (§4.2.1.13). A base CRL carrying `freshestCRL` is used as
 * complete as of its `thisUpdate`; the delta is not fetched.
 *
 * An unavailability has a stable `reason`, a `detail` in this module's own
 * words, and any library error as `cause` — never as text in `detail`, since
 * it describes bytes a CA or network path supplied. It is marked `outage` when
 * the source failed (`isSourceFailure`, `unparseable`, `stale`) rather than
 * the certificate's shape; a lookup over several points is an outage only if
 * every failed point was. Under `on-unavailable = "reject"` the validator
 * answers an outage as 503 and anything else as a verdict on the certificate.
 */

import { createHash } from "node:crypto";
import * as pkijs from "pkijs";
import { type AlgorithmPolicy, checkSignatureAlgorithm } from "./algorithms.mjs";
import { checkCrlCriticalExtensions, extensionValueParsed } from "./criticalExtensions.mjs";
import { DEFAULT_ALGORITHM_POLICY } from "./defaults.mjs";
import { type GuardedFetch, isSourceFailure } from "./fetchGuard.mjs";

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
 * stable — audit logs read them. The `unsupported_*` reasons are shapes RFC
 * 5280 permits that this resolver recognises but does not implement.
 * `algorithm_not_permitted` is a CRL signed outside
 * `mtls.fullPki.signatureAlgorithms`, the path's own policy.
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
 * named by its first URI and never tried.
 */
export interface CrlPointUnavailable {
	readonly url: string;
	readonly reason: CrlUnavailableReason;
	readonly detail: string;
	/** The library error behind `reason`, when one threw. */
	readonly cause?: unknown;
	/** The source did not answer usefully (see the module header), rather than the certificate's shape. */
	readonly outage?: true;
}

export type CrlLookup =
	| {
			readonly ok: true;
			readonly crls: readonly pkijs.CertificateRevocationList[];
			/**
			 * Distribution points that yielded no CRL — one entry per URI tried,
			 * and one per unsupported point — empty when every point was used.
			 * A lookup can be `ok` and incomplete at once; whether that is an
			 * answer is the caller's `on-unavailable` decision.
			 */
			readonly unavailable: readonly CrlPointUnavailable[];
	  }
	| {
			readonly ok: false;
			readonly reason: CrlUnavailableReason;
			readonly detail: string;
			/** The last failure's library error, beside its `reason`, when one threw. */
			readonly cause?: unknown;
			/** Every point that could not be used was an outage (see the module header). */
			readonly outage?: true;
			/**
			 * Each point that could not be used, when the certificate named any:
			 * what a caller that reports every source one by one reads.
			 */
			readonly points?: readonly CrlPointUnavailable[];
	  };

/** One audit-trail line per URI that could not be used. */
export const describeUnavailable = (points: readonly CrlPointUnavailable[]): string =>
	points.map((point) => `${point.url}: ${point.reason} (${point.detail})`).join("; ");

/**
 * How long an unusable distribution point is remembered, in milliseconds.
 * Not configurable: it absorbs a burst (no fetch per request on the token
 * endpoint's critical path), and a CA that recovers must be noticed in
 * seconds, not in the hours `cache-ttl-seconds` is measured in.
 */
export const CRL_NEGATIVE_CACHE_TTL_MS = 30_000;

export type CrlDistributionPoints =
	| {
			readonly ok: true;
			/** One entry per usable distribution point: that point's HTTP(S) URIs, in order. */
			readonly points: readonly (readonly string[])[];
			/**
			 * Distribution points carrying `reasons` or `cRLIssuer`, one entry per
			 * point, never fetched. Reported beside the usable points so the
			 * caller can count them as gaps under `"reject"`.
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
 * Why a distribution point is unsupported. With `reasons`, no single CRL is
 * the complete answer (RFC 5280 §6.3.3 reasons-mask bookkeeping is not
 * implemented); with `cRLIssuer`, the CRL is signed by someone other than the
 * certificate's issuer, the only key verified here.
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
 * Read the distribution points a certificate advertises: one URI list per
 * usable point, plus the unsupported points. Names within one point are
 * alternatives for the same CRL (RFC 5280 §4.2.1.13); separate points are
 * not, so a point is reported only when none of its names answered.
 *
 * Only absolute HTTP(S) URIs are kept. A point with none (LDAP, a directory
 * name) is left out rather than counted as failed, so an LDAP point beside an
 * HTTP one does not make a certificate unavailable under `"reject"`. A point
 * carrying `reasons` or `cRLIssuer` is reported as
 * `unsupported_distribution_point` beside the usable points, never fetched;
 * a plain point beside it still answers for every reason code. Only a
 * certificate with no usable point fails as a whole.
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
			readonly cause?: unknown;
			readonly outage?: true;
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
			readonly cause?: unknown;
			readonly outage?: true;
	  };

/** What one distribution-point URI produced, after every check. */
type UrlOutcome =
	| { readonly ok: true; readonly crl: pkijs.CertificateRevocationList }
	| {
			readonly ok: false;
			readonly reason: CrlUnavailableReason;
			readonly detail: string;
			readonly cause?: unknown;
			readonly outage?: true;
	  };

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
	 * The signature-algorithm policy the validated path is held to, applied to
	 * each CRL's signature too. Defaults to `DEFAULT_ALGORITHM_POLICY`, the
	 * strict policy, so omitting it can only make the check stricter;
	 * `validate.mts` passes the configured policy.
	 */
	readonly algorithms?: AlgorithmPolicy;
	/** Bound on cache size, so a large trust set cannot grow it without limit. */
	readonly maxCacheEntries?: number;
}

export interface CrlResolver {
	/**
	 * Fetch (or reuse) the CRLs covering `certificate`, one per distribution
	 * point, verified against `issuer` (the next certificate up the validated
	 * path). Only a CRL whose signature verifies against `issuer`'s key is
	 * returned or cached. Concurrent calls for one point share a fetch, and an
	 * unusable point is not retried within `CRL_NEGATIVE_CACHE_TTL_MS`.
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
): Promise<{ ok: true } | { ok: false; detail: string; cause?: unknown }> => {
	if (!issuerMaySignCrls(issuer)) {
		return { ok: false, detail: "the issuing CA's keyUsage omits cRLSign (RFC 5280 §6.3.3)" };
	}
	let verified: boolean;
	try {
		verified = await crl.verify({ issuerCertificate: issuer });
	} catch (err) {
		// Thrown rather than answered `false`: a signature value WebCrypto
		// cannot read, a key it cannot import. Its text stays on the cause.
		return { ok: false, detail: "signature check failed", cause: err };
	}
	return verified
		? { ok: true }
		: { ok: false, detail: "signature does not verify against the issuing CA" };
};

/**
 * Whether the CRL claims a scope this resolver can honour. RFC 5280 §6.3.3
 * (b) (matching `issuingDistributionPoint`) and (c) (combining a delta with
 * its base) are not implemented, so a scoped CRL or a delta is reported as
 * unsupported rather than read as complete. Both extensions are detected
 * regardless of criticality: a CA that marks one non-critical has still
 * scoped its CRL.
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
	const algorithms = options.algorithms ?? DEFAULT_ALGORITHM_POLICY;
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

	const remember = (
		url: string,
		failure: {
			readonly reason: RememberedReason;
			readonly detail: string;
			readonly cause?: unknown;
			readonly outage?: true;
		},
		now: Date,
	): void =>
		store(unavailableKey(url), {
			kind: "unavailable",
			reason: failure.reason,
			detail: failure.detail,
			...(failure.cause !== undefined ? { cause: failure.cause } : {}),
			...(failure.outage ? { outage: true } : {}),
			expiresAt: now.getTime() + CRL_NEGATIVE_CACHE_TTL_MS,
		});

	const fetchAndParse = async (url: string): Promise<Loaded> => {
		const fetched = await options.fetch(url);
		if (!fetched.ok) {
			return {
				ok: false,
				reason: "fetch_failed",
				detail: `${fetched.reason} (${fetched.detail})`,
				...(fetched.cause !== undefined ? { cause: fetched.cause } : {}),
				...(isSourceFailure(fetched.reason) ? { outage: true } : {}),
			};
		}
		try {
			return { ok: true, crl: pkijs.CertificateRevocationList.fromBER(fetched.bytes) };
		} catch (err) {
			return {
				ok: false,
				reason: "unparseable",
				detail: "not a DER CRL",
				cause: err,
				outage: true,
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
				...(unavailable.cause !== undefined ? { cause: unavailable.cause } : {}),
				...(unavailable.outage ? { outage: true } : {}),
			};
		}

		const loaded = await load(url);
		if (!loaded.ok) {
			remember(url, loaded, now);
			return loaded;
		}

		// Extensions before the signature, so that a CRL this resolver cannot
		// use is named as such and remembered — see the module header. Only
		// its shape is judged, and the answer is at most "do not use it".
		const critical = checkCrlCriticalExtensions(loaded.crl);
		if (!critical.ok) {
			remember(url, { reason: "unsupported_critical_extension", detail: critical.detail }, now);
			return { ok: false, reason: "unsupported_critical_extension", detail: critical.detail };
		}
		const scope = checkScope(loaded.crl);
		if (!scope.ok) {
			remember(url, { reason: "unsupported_crl_scope", detail: scope.detail }, now);
			return { ok: false, reason: "unsupported_crl_scope", detail: scope.detail };
		}

		// The signature algorithm before the signature, for the same reason:
		// a refusal on the OID the CRL names, safe to remember, and remembered
		// so a SHA-1 CA does not cost one guarded fetch per request.
		// `signatureAlgorithm` is the field pkijs verifies with; RFC 5280
		// §5.1.1.2 requires the tbsCertList copy to match it.
		const algorithm = checkSignatureAlgorithm(
			loaded.crl.signatureAlgorithm.algorithmId,
			algorithms,
		);
		if (!algorithm.ok) {
			const detail = `the CRL's signature algorithm ${algorithm.detail}`;
			remember(url, { reason: "algorithm_not_permitted", detail }, now);
			return { ok: false, reason: "algorithm_not_permitted", detail };
		}

		// Nothing an unverified CRL says is acted on — not even its dates — so
		// the signature comes before freshness, and a failure here is the one
		// outcome that is never remembered: a single injected response must
		// not pin a refusal for anyone.
		const signature = await verifySignature(loaded.crl, issuer);
		if (!signature.ok) {
			return {
				ok: false,
				reason: "bad_signature",
				detail: signature.detail,
				...(signature.cause !== undefined ? { cause: signature.cause } : {}),
			};
		}

		const fresh = freshness(loaded.crl, now);
		if (!fresh.ok) {
			// Not stored as usable; remembered for the negative window only, so
			// a source that stopped publishing is noticed within seconds once it
			// resumes. A list past its `nextUpdate` is the source's outage (the CA
			// has not published); one with none at all is its shape.
			const failure = {
				reason: fresh.reason,
				detail: fresh.detail,
				...(fresh.reason === "stale" ? { outage: true as const } : {}),
			};
			remember(url, failure, now);
			return { ok: false, ...failure };
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
			// Unsupported points are reported with the rest, never fetched; the
			// usable points are still consulted.
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
					failures.push({
						url,
						reason: outcome.reason,
						detail: outcome.detail,
						...(outcome.cause !== undefined ? { cause: outcome.cause } : {}),
						...(outcome.outage ? { outage: true } : {}),
					});
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
					...(last?.cause !== undefined ? { cause: last.cause } : {}),
					...(unavailable.length > 0 && unavailable.every((point) => point.outage)
						? { outage: true }
						: {}),
					points: unavailable,
				};
			}
			return { ok: true, crls, unavailable };
		},
	};
};
