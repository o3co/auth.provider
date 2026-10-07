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
 *  - a URL that could not be used — unreachable, unparseable, or serving a
 *    CRL that is stale or undated — is remembered as unavailable for
 *    `CRL_NEGATIVE_CACHE_TTL_MS`, so a stuck endpoint costs one probe per
 *    window rather than one per request. `bad_signature` is exempt, per the
 *    section above.
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
 * is never handed revocation material at all.
 */
import { createHash } from "node:crypto";
import * as pkijs from "pkijs";
/** OID of the `cRLDistributionPoints` extension (RFC 5280 §4.2.1.13). */
const OID_CRL_DISTRIBUTION_POINTS = "2.5.29.31";
/** OID of `keyUsage` (RFC 5280 §4.2.1.3). */
const OID_KEY_USAGE = "2.5.29.15";
/** `cRLSign` bit of `keyUsage`, MSB-first within the first octet. */
const KEY_USAGE_CRL_SIGN = 0x02;
/** `GeneralName` tag for `uniformResourceIdentifier`. */
const GENERAL_NAME_URI = 6;
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
/**
 * Collect the HTTP(S) distribution-point URLs a certificate advertises.
 *
 * A `DistributionPoint` can also carry a `cRLIssuer` or name the CRL by a
 * relative name; both are ignored here. Anything not expressible as a
 * fetchable absolute URI produces no URL, which the caller sees as
 * `no_distribution_point` — an honest "cannot check" rather than a silent
 * pass.
 */
export const crlDistributionUrls = (certificate) => {
    const extension = certificate.extensions?.find((ext) => ext.extnID === OID_CRL_DISTRIBUTION_POINTS);
    const parsed = extension?.parsedValue;
    if (!parsed?.distributionPoints)
        return [];
    const urls = [];
    for (const point of parsed.distributionPoints) {
        const name = point.distributionPoint;
        if (!Array.isArray(name))
            continue;
        for (const generalName of name) {
            if (generalName.type === GENERAL_NAME_URI && typeof generalName.value === "string") {
                urls.push(generalName.value);
            }
        }
    }
    return urls;
};
const DEFAULT_MAX_CACHE_ENTRIES = 256;
/**
 * Whether `issuer` is entitled to sign CRLs at all: RFC 5280 §6.3.3 (f) — its
 * `keyUsage`, when present, MUST include `cRLSign`. Being entitled to sign
 * certificates is not being entitled to publish revocation lists, and the
 * bit is the CA's own statement about which of the two this key does.
 * Absence is unconstrained, as for every other `keyUsage` check in this arm.
 */
const issuerMaySignCrls = (issuer) => {
    const extension = issuer.extensions?.find((ext) => ext.extnID === OID_KEY_USAGE);
    if (extension === undefined)
        return true;
    const parsed = extension.parsedValue;
    const bytes = parsed?.valueBlock?.valueHexView;
    // Present but unreadable is a restriction that cannot be honoured, not an
    // absent one — the same distinction `checkLeafKeyUsage` draws.
    if (bytes === undefined || bytes.length === 0)
        return false;
    return ((bytes[0] ?? 0) & KEY_USAGE_CRL_SIGN) === KEY_USAGE_CRL_SIGN;
};
/**
 * Verify that `issuer` published `crl`. `verify` also answers `false` when
 * the CRL's issuer name is not `issuer`'s subject and when the CRL carries a
 * critical extension pkijs does not know — both of which are "not a CRL this
 * issuer published", which is the question being asked.
 */
const verifySignature = async (crl, issuer) => {
    if (!issuerMaySignCrls(issuer)) {
        return { ok: false, detail: "the issuing CA's keyUsage omits cRLSign (RFC 5280 §6.3.3)" };
    }
    let verified;
    try {
        verified = await crl.verify({ issuerCertificate: issuer });
    }
    catch (err) {
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
 * A cache entry is keyed by the distribution point *and* the key the CRL was
 * verified against. Two CAs can share a subject name — a key rollover keeps
 * the DN — and a CRL accepted for one must never be handed to a certificate
 * the other issued.
 */
const issuerKeyId = (issuer) => createHash("sha256")
    .update(new Uint8Array(issuer.subjectPublicKeyInfo.toSchema().toBER(false)))
    .digest("hex");
const usableKey = (url, issuerId) => `crl:${url}\n${issuerId}`;
/**
 * Unavailability is a property of the distribution point, not of who asked,
 * so it is remembered per URL.
 */
const unavailableKey = (url) => `down:${url}`;
export const createCrlResolver = (options) => {
    const cache = new Map();
    const maxEntries = options.maxCacheEntries ?? DEFAULT_MAX_CACHE_ENTRIES;
    /** Fetches in progress, so concurrent misses on one URL issue one request. */
    const inFlight = new Map();
    /**
     * A CRL with no `nextUpdate` is treated as unusable rather than as
     * eternally fresh. RFC 5280 §5.1.2.5 requires conforming CAs to include
     * it, and without it there is no way to tell a current CRL from one
     * captured years ago and replayed — which is exactly the position an
     * attacker who has had a certificate revoked wants us in.
     */
    const freshness = (crl, now) => {
        const nextUpdate = crl.nextUpdate?.value;
        if (nextUpdate === undefined)
            return { ok: false, reason: "no_next_update" };
        if (nextUpdate.getTime() <= now.getTime())
            return { ok: false, reason: "stale" };
        return {
            ok: true,
            expiresAt: Math.min(nextUpdate.getTime(), now.getTime() + options.cacheTtlSeconds * 1000),
        };
    };
    const store = (key, entry) => {
        if (cache.size >= maxEntries && !cache.has(key)) {
            // Oldest insertion first — Map preserves insertion order. A CRL cache
            // has no hot/cold distinction worth a real eviction policy; the bound
            // exists so the map cannot grow without limit, not to maximise hits.
            const oldest = cache.keys().next();
            if (!oldest.done)
                cache.delete(oldest.value);
        }
        cache.set(key, entry);
    };
    const remember = (url, reason, detail, now) => store(unavailableKey(url), {
        kind: "unavailable",
        reason,
        detail,
        expiresAt: now.getTime() + CRL_NEGATIVE_CACHE_TTL_MS,
    });
    const fetchAndParse = async (url) => {
        const fetched = await options.fetch(url);
        if (!fetched.ok) {
            return { ok: false, reason: "fetch_failed", detail: `${fetched.reason} (${fetched.detail})` };
        }
        try {
            return { ok: true, crl: pkijs.CertificateRevocationList.fromBER(fetched.bytes) };
        }
        catch (err) {
            return {
                ok: false,
                reason: "unparseable",
                detail: `not a DER CRL (${err instanceof Error ? err.message : String(err)})`,
            };
        }
    };
    /** Fetch `url`, joining a fetch of it that is already in progress. */
    const load = (url) => {
        const existing = inFlight.get(url);
        if (existing !== undefined)
            return existing;
        const pending = fetchAndParse(url).finally(() => inFlight.delete(url));
        inFlight.set(url, pending);
        return pending;
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
            const crls = [];
            const problems = [];
            let lastReason = "fetch_failed";
            for (const url of urls) {
                const usable = cache.get(usableKey(url, issuerId));
                if (usable?.kind === "crl" && usable.expiresAt > now.getTime()) {
                    crls.push(usable.crl);
                    continue;
                }
                const unavailable = cache.get(unavailableKey(url));
                if (unavailable?.kind === "unavailable" && unavailable.expiresAt > now.getTime()) {
                    lastReason = unavailable.reason;
                    problems.push(`${url}: ${unavailable.reason} (${unavailable.detail}; not retried yet)`);
                    continue;
                }
                const loaded = await load(url);
                if (!loaded.ok) {
                    remember(url, loaded.reason, loaded.detail, now);
                    lastReason = loaded.reason;
                    problems.push(`${url}: ${loaded.reason} (${loaded.detail})`);
                    continue;
                }
                // Nothing an unverified CRL says is acted on — not even its dates —
                // so the signature comes before freshness, and a failure here is
                // the one outcome that is never remembered: a single injected
                // response must not pin a refusal for anyone.
                const signature = await verifySignature(loaded.crl, issuer);
                if (!signature.ok) {
                    lastReason = "bad_signature";
                    problems.push(`${url}: bad_signature (${signature.detail})`);
                    continue;
                }
                const fresh = freshness(loaded.crl, now);
                if (!fresh.ok) {
                    // Not stored as usable. The failure is remembered for the negative
                    // window only, so a responder that has stopped publishing costs
                    // one probe per window rather than one per request — and is
                    // noticed within seconds once it publishes again.
                    remember(url, fresh.reason, fresh.reason, now);
                    lastReason = fresh.reason;
                    problems.push(`${url}: ${fresh.reason}`);
                    continue;
                }
                store(usableKey(url, issuerId), {
                    kind: "crl",
                    crl: loaded.crl,
                    expiresAt: fresh.expiresAt,
                });
                crls.push(loaded.crl);
            }
            if (crls.length === 0) {
                return { ok: false, reason: lastReason, detail: problems.join("; ") };
            }
            return { ok: true, crls };
        },
    };
};
