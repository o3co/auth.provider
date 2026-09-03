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
 * ### The failure that matters
 *
 * `pkijs` skips its revocation block entirely when it is handed no CRLs. So
 * "the CRL server was down" and "the certificate is not revoked" arrive at
 * the engine as the same input and produce the same verdict: valid. Whether
 * that is acceptable is an operator's decision about their threat model, not
 * something a library gets to make silently — so this module reports
 * unavailability as its own outcome, and the caller applies the configured
 * `on-unavailable` policy before the engine is ever consulted.
 */

import { createHash } from "node:crypto";
import * as pkijs from "pkijs";
import type { GuardedFetch } from "./fetchGuard.mjs";

/** OID of the `cRLDistributionPoints` extension (RFC 5280 §4.2.1.13). */
const OID_CRL_DISTRIBUTION_POINTS = "2.5.29.31";

/** OID of `keyUsage` (RFC 5280 §4.2.1.3). */
const OID_KEY_USAGE = "2.5.29.15";

/** `cRLSign` bit of `keyUsage`, MSB-first within the first octet. */
const KEY_USAGE_CRL_SIGN = 0x02;

/** `GeneralName` tag for `uniformResourceIdentifier`. */
const GENERAL_NAME_URI = 6;

export type CrlUnavailableReason =
	| "no_distribution_point"
	| "fetch_failed"
	| "unparseable"
	| "no_next_update"
	| "stale"
	| "bad_signature";

export type CrlLookup =
	| { readonly ok: true; readonly crls: readonly pkijs.CertificateRevocationList[] }
	| { readonly ok: false; readonly reason: CrlUnavailableReason; readonly detail: string };

/**
 * Collect the HTTP(S) distribution-point URLs a certificate advertises.
 *
 * A `DistributionPoint` can also carry a `cRLIssuer` or name the CRL by a
 * relative name; both are ignored here. Anything not expressible as a
 * fetchable absolute URI produces no URL, which the caller sees as
 * `no_distribution_point` — an honest "cannot check" rather than a silent
 * pass.
 */
export const crlDistributionUrls = (certificate: pkijs.Certificate): readonly string[] => {
	const extension = certificate.extensions?.find(
		(ext) => ext.extnID === OID_CRL_DISTRIBUTION_POINTS,
	);
	const parsed = extension?.parsedValue as pkijs.CRLDistributionPoints | undefined;
	if (!parsed?.distributionPoints) return [];

	const urls: string[] = [];
	for (const point of parsed.distributionPoints) {
		const name = point.distributionPoint;
		if (!Array.isArray(name)) continue;
		for (const generalName of name) {
			if (generalName.type === GENERAL_NAME_URI && typeof generalName.value === "string") {
				urls.push(generalName.value);
			}
		}
	}
	return urls;
};

interface CacheEntry {
	readonly crl: pkijs.CertificateRevocationList;
	/** Epoch millis after which this entry must be re-fetched. */
	readonly expiresAt: number;
}

export interface CrlResolverOptions {
	readonly fetch: GuardedFetch;
	/**
	 * Upper bound on how long a CRL is reused, in seconds. The CRL's own
	 * `nextUpdate` still wins when it is sooner — this only stops a CA that
	 * publishes a year-long `nextUpdate` from pinning a stale answer in memory
	 * for a year.
	 */
	readonly cacheTtlSeconds: number;
	/** Bound on cache size, so a large trust set cannot grow it without limit. */
	readonly maxCacheEntries?: number;
}

export interface CrlResolver {
	/**
	 * Fetch (or reuse) the CRLs covering `certificate`, verified against
	 * `issuer` — the certificate that issued it, i.e. the next element up the
	 * validated path. Only a CRL whose signature verifies against `issuer`'s
	 * key is ever returned or cached.
	 */
	resolve(certificate: pkijs.Certificate, issuer: pkijs.Certificate, now: Date): Promise<CrlLookup>;
	/** Entry count — for tests and for a future metric. */
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
 * the CRL's issuer name is not `issuer`'s subject and when the CRL carries a
 * critical extension pkijs does not know — both of which are "not a CRL this
 * issuer published", which is the question being asked.
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
		return { ok: false, detail: `signature check failed: ${(err as Error).message}` };
	}
	return verified
		? { ok: true }
		: { ok: false, detail: "signature does not verify against the issuing CA" };
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

const cacheKey = (url: string, issuerId: string): string => `${url}\n${issuerId}`;

export const createCrlResolver = (options: CrlResolverOptions): CrlResolver => {
	const cache = new Map<string, CacheEntry>();
	const maxEntries = options.maxCacheEntries ?? DEFAULT_MAX_CACHE_ENTRIES;

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
	): { ok: true; expiresAt: number } | { ok: false; reason: "no_next_update" | "stale" } => {
		const nextUpdate = crl.nextUpdate?.value;
		if (nextUpdate === undefined) return { ok: false, reason: "no_next_update" };
		if (nextUpdate.getTime() <= now.getTime()) return { ok: false, reason: "stale" };
		return {
			ok: true,
			expiresAt: Math.min(nextUpdate.getTime(), now.getTime() + options.cacheTtlSeconds * 1000),
		};
	};

	const store = (url: string, entry: CacheEntry): void => {
		if (cache.size >= maxEntries && !cache.has(url)) {
			// Oldest insertion first — Map preserves insertion order. A CRL cache
			// has no hot/cold distinction worth a real eviction policy; the bound
			// exists so the map cannot grow without limit, not to maximise hits.
			const oldest = cache.keys().next();
			if (!oldest.done) cache.delete(oldest.value);
		}
		cache.set(url, entry);
	};

	return {
		size: () => cache.size,

		resolve: async (certificate, issuer, now) => {
			const urls = crlDistributionUrls(certificate);
			if (urls.length === 0) {
				return {
					ok: false,
					reason: "no_distribution_point",
					detail: "certificate advertises no cRLDistributionPoints URI",
				};
			}

			const issuerId = issuerKeyId(issuer);
			const crls: pkijs.CertificateRevocationList[] = [];
			const problems: string[] = [];
			let lastReason: CrlUnavailableReason = "fetch_failed";

			for (const url of urls) {
				const key = cacheKey(url, issuerId);
				const cached = cache.get(key);
				if (cached !== undefined && cached.expiresAt > now.getTime()) {
					crls.push(cached.crl);
					continue;
				}

				const fetched = await options.fetch(url);
				if (!fetched.ok) {
					lastReason = "fetch_failed";
					problems.push(`${url}: ${fetched.reason} (${fetched.detail})`);
					continue;
				}

				let crl: pkijs.CertificateRevocationList;
				try {
					crl = pkijs.CertificateRevocationList.fromBER(fetched.bytes);
				} catch (err) {
					lastReason = "unparseable";
					problems.push(`${url}: not a DER CRL (${(err as Error).message})`);
					continue;
				}

				// Nothing an unverified CRL says is acted on — not even its dates —
				// so the signature comes before freshness.
				const signature = await verifySignature(crl, issuer);
				if (!signature.ok) {
					lastReason = "bad_signature";
					problems.push(`${url}: bad_signature (${signature.detail})`);
					continue;
				}

				const fresh = freshness(crl, now);
				if (!fresh.ok) {
					lastReason = fresh.reason;
					problems.push(`${url}: ${fresh.reason}`);
					// A stale CRL is deliberately not cached: caching it would let a
					// responder that has stopped publishing keep us from ever
					// retrying.
					continue;
				}

				store(key, { crl, expiresAt: fresh.expiresAt });
				crls.push(crl);
			}

			if (crls.length === 0) {
				return { ok: false, reason: lastReason, detail: problems.join("; ") };
			}
			return { ok: true, crls };
		},
	};
};
