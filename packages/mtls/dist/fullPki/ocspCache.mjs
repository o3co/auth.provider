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
import { CRL_NEGATIVE_CACHE_TTL_MS } from "./crl.mjs";
import { markOutage } from "./ocspAnswer.mjs";
/**
 * How long a responder that could not be used is remembered, in
 * milliseconds. The CRL resolver's window, for the CRL resolver's reasons.
 */
export const OCSP_NEGATIVE_CACHE_TTL_MS = CRL_NEGATIVE_CACHE_TTL_MS;
const RESPONDER_FAILURES = new Set([
    "fetch_failed",
    "unparseable",
    "responder_error",
    "responder_revoked",
    "responder_status_unavailable",
]);
const CERTIFICATE_FAILURES = new Set([
    "no_matching_response",
    "unsupported_critical_extension",
    "algorithm_not_permitted",
    "nonce_missing",
    "not_yet_valid",
    "stale",
    "unknown",
]);
export const DEFAULT_MAX_CACHE_ENTRIES = 1024;
export const serialHex = (certificate) => Buffer.from(certificate.serialNumber.valueBlock.valueHexView).toString("hex");
const statusKey = (url, issuerId, serial) => `ocsp:${url}\n${issuerId}\n${serial}`;
const responderDownKey = (url) => `down:${url}`;
const certificateDownKey = (url, issuerId, serial) => `down:${url}\n${issuerId}\n${serial}`;
export const createOcspCache = (maxEntries, query, checkResponder) => {
    const cache = new Map();
    /** Requests in progress, so concurrent misses on one certificate issue one request. */
    const inFlight = new Map();
    const store = (key, entry) => {
        if (cache.size >= maxEntries && !cache.has(key)) {
            // Oldest insertion first, as in `crl.mts`: the bound exists so the
            // map cannot grow without limit, not to maximise hits.
            const oldest = cache.keys().next();
            if (!oldest.done)
                cache.delete(oldest.value);
        }
        cache.set(key, entry);
    };
    const remember = (key, reason, failure, now) => store(key, {
        kind: "unavailable",
        reason,
        detail: failure.detail,
        ...(failure.cause !== undefined ? { cause: failure.cause } : {}),
        ...(failure.outage ? { outage: true } : {}),
        expiresAt: now.getTime() + OCSP_NEGATIVE_CACHE_TTL_MS,
    });
    /** `query`, joining a request for the same certificate that is already in flight. */
    const load = (key, url, certificate, issuer, now) => {
        const existing = inFlight.get(key);
        if (existing !== undefined)
            return existing;
        const pending = query(url, certificate, issuer, now)
            .then(markOutage)
            .finally(() => inFlight.delete(key));
        inFlight.set(key, pending);
        return pending;
    };
    /** What `url` says about `certificate` — from the cache, or by asking now. */
    const lookup = async (url, certificate, issuer, issuerId, serial, now) => {
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
            remember(responderDownKey(url), answer.reason, answer, now);
        }
        else if (CERTIFICATE_FAILURES.has(answer.reason)) {
            remember(certificateDownKey(url, issuerId, serial), answer.reason, answer, now);
        }
        // `bad_signature` and `nonce_mismatch` are left unremembered on purpose.
        return answer;
    };
    return { lookup, size: () => cache.size };
};
