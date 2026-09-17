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
 * Client ID Metadata Documents (#529) —
 * draft-ietf-oauth-client-id-metadata-document, the client registration the
 * MCP authorization spec (2026-07-28) makes the SHOULD for hosted clients now
 * that Dynamic Client Registration is deprecated there.
 *
 * A client identifies itself with an `https` URL, and the document at that
 * URL *is* its registration: `client_id` (the URL itself), `redirect_uris`,
 * `client_name`, `client_uri`, and the rest of the RFC 7591 vocabulary. This
 * module fetches, validates and caches such documents and hands back the
 * `PublicClient` the rest of the server already knows how to treat — a
 * public client (`token_endpoint_auth_method: none`, PKCE S256 required),
 * never first-party, so it goes through the consent step (#527).
 *
 * ## What is refused before anything is fetched
 *
 * A `client_id` that is not a document URL — not `https`, no path, a
 * fragment, credentials, dot segments, a query string, an IP literal, a
 * loopback name — is simply "not a client" (`findById` → `null`), and so is a
 * host outside the operator's `allowedHosts` or inside `deniedHosts`. Then
 * the name is resolved and every address it resolves to must be public:
 * one inside an RFC 6890 special-use range (the cloud metadata endpoint, a
 * private network, this host) refuses the whole lookup. That is the SSRF
 * guard the draft requires, and it runs before the socket opens. A
 * rebinding between the check and the connect is the residual the draft
 * accepts as well; the allow/deny lists are the operator's lever against it.
 *
 * ## The fetch
 *
 * `GET`, no redirects followed (a 3xx is an error — the draft is explicit),
 * a timeout, a byte cap checked on `Content-Length` first and on the stream
 * second (a hostile host omits the header), and only `200` with a JSON body
 * counts. Errors and invalid documents are never cached; a valid one is
 * cached per URL for `Cache-Control: max-age` bounded above by
 * `cacheMaxAgeMs`, with an `ETag` revalidated by `If-None-Match` when it
 * expires. Concurrent lookups of one URL share one fetch.
 *
 * ## The document
 *
 * `client_id` must equal the URL by simple string comparison; `redirect_uris`
 * must be a non-empty list of URIs this server would accept at registration
 * (`checkRedirectUri`); `token_endpoint_auth_method`, when present, must be
 * `none` — a shared-secret method is forbidden by the draft, and
 * `private_key_jwt` is refused because the draft's client is one that proves
 * nothing beyond holding its own URL: the keys would have to come from the
 * same attacker-authored document that names them, so the method would
 * authenticate the document rather than the client. This server does support
 * `private_key_jwt` for registered clients (#484); `client_secret` must be
 * absent; `grant_types` must include
 * `authorization_code` and only its RFC 7591 companions survive;
 * `response_types` must admit `code`. `scope` is intersected with the
 * operator's `allowedScopes` ceiling, and `allowedAudiences` — the resource
 * servers this authorization server protects — is the operator's too: a
 * document says who the client is, never what it may reach.
 *
 * A pre-registered client with the same `client_id` wins; the document is
 * not fetched.
 */
import { promises as dns } from "node:dns";
import { isIP } from "node:net";
import { checkRedirectUri, isLoopbackHostname, isSpecialUseAddress, } from "@o3co/auth-provider-core";
export const DEFAULT_CIMD_MAX_BYTES = 5 * 1024;
/**
 * How many documents the resolver remembers at once. An unauthenticated
 * caller chooses the keys — any URL that serves a valid document is a
 * `client_id` — so the map is bounded, like the CRL and OCSP caches.
 */
export const DEFAULT_CIMD_MAX_CACHE_ENTRIES = 256;
export const DEFAULT_CIMD_TIMEOUT_MS = 5_000;
export const DEFAULT_CIMD_CACHE_MAX_AGE_MS = 10 * 60 * 1000;
/** The grant types a document may claim; anything else is dropped, `authorization_code` is required. */
const SUPPORTED_GRANT_TYPES = new Set(["authorization_code", "refresh_token"]);
/**
 * Whether `clientId` has the shape of a Client ID Metadata Document URL
 * (draft §3.1): `https`, a path, no fragment, no credentials, no dot segments,
 * no query string, and a host that is a name rather than an address.
 *
 * Shape only — the host policy and the resolution check are the resolver's.
 * Exported so `/authorize` and the token endpoint can tell "not a client at
 * all" from "a document URL we could not honour" in their logs.
 */
export function isClientIdMetadataDocumentUrl(clientId) {
    let url;
    try {
        url = new URL(clientId);
    }
    catch {
        return false;
    }
    if (url.protocol !== "https:")
        return false;
    if (url.href !== clientId)
        return false; // not in canonical form: the document's client_id could never equal it
    if (url.pathname === "" || url.pathname === "/")
        return false;
    if (url.hash !== "" || clientId.endsWith("#"))
        return false;
    if (url.username !== "" || url.password !== "")
        return false;
    if (url.search !== "" || clientId.endsWith("?"))
        return false;
    if (url.pathname.split("/").some((segment) => segment === "." || segment === ".."))
        return false;
    if (isIP(url.hostname) !== 0 || url.hostname.startsWith("["))
        return false;
    // A trailing dot is the DNS root — `client.example.` and `client.example`
    // resolve to one host, and TLS accepts the certificate issued for the
    // undotted name — but it survives `new URL(...).href` unchanged, so the
    // canonical-form check above passes it. The host policy compares strings:
    // `allowedHosts` fails closed on the dotted spelling (it matches nothing)
    // while `deniedHosts` failed open, so a denied host was reachable by
    // adding one character. Refused here rather than normalised, because a
    // client id is a string a document has to echo exactly, and there is no
    // reason for one to carry the root label.
    if (url.hostname.endsWith("."))
        return false;
    if (isLoopbackHostname(url.hostname))
        return false;
    return true;
}
const hostMatches = (patterns, hostname) => (patterns ?? []).some((pattern) => {
    const p = pattern.toLowerCase();
    const h = hostname.toLowerCase();
    return p.startsWith(".") ? h === p.slice(1) || h.endsWith(p) : h === p;
});
/**
 * How long a cached registration outlives a revalidation this server could
 * not complete — a DNS blip, a 5xx, a timeout.
 *
 * The distinction #408 draws, applied to the cache: refusing a client
 * because someone else's server is down tells the caller their credential
 * is bad when the truth is an outage. On a cold lookup there is nothing to
 * serve and `null` is the only answer; on a warm one the registration this
 * server already validated is a better answer than breaking a working
 * client. A document the server **rejected** is not this: that client
 * stopped being a client, and its entry goes immediately.
 */
export const DEFAULT_CIMD_STALE_IF_ERROR_MS = 5 * 60 * 1000;
/**
 * How long a refusal is remembered.
 *
 * Failures were never cached, so every distinct URL-shaped `client_id` cost
 * a DNS resolution, a TLS handshake and a GET on **every** request: an
 * unauthenticated caller could pin sockets against a tarpit of its own, or
 * point this server's address at a third party and have it re-fetch a 404
 * indefinitely. Short, because a client that fixes its document must not be
 * locked out for the life of the process.
 */
export const DEFAULT_CIMD_NEGATIVE_CACHE_MS = 60 * 1000;
/**
 * How many documents may be fetched at once, across every client id.
 *
 * De-duplication was per URL, so distinct ids fanned out without limit and
 * N slow hosts held N sockets for the whole timeout each. The cap makes the
 * outbound cost of an unauthenticated request bounded rather than
 * proportional to how many ids the caller can invent.
 */
export const DEFAULT_CIMD_MAX_CONCURRENT_FETCHES = 8;
/**
 * The `max-age` a `Cache-Control` header grants, or `undefined` when it grants
 * none (`no-store`, `no-cache`, or absent). `private` is fine: this server is
 * the one client of the document.
 */
const maxAgeMsOf = (cacheControl) => {
    if (cacheControl === null)
        return undefined;
    const directives = cacheControl.split(",").map((d) => d.trim().toLowerCase());
    if (directives.includes("no-store") || directives.includes("no-cache"))
        return 0;
    const maxAge = directives.find((d) => d.startsWith("max-age="));
    if (maxAge === undefined)
        return undefined;
    const seconds = Number(maxAge.slice("max-age=".length));
    return Number.isFinite(seconds) && seconds >= 0 ? seconds * 1000 : undefined;
};
class DocumentRejected extends Error {
}
/** Read at most `limit` bytes of `res`; throw past it, header or stream. */
async function readCapped(res, limit) {
    const declared = Number(res.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > limit) {
        await res.body?.cancel().catch(() => undefined);
        throw new DocumentRejected(`document exceeds ${limit} bytes (Content-Length: ${declared})`);
    }
    if (res.body === null)
        return "";
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let text = "";
    let read = 0;
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done)
                break;
            read += value.byteLength;
            if (read > limit)
                throw new DocumentRejected(`document exceeds ${limit} bytes`);
            text += decoder.decode(value, { stream: true });
        }
    }
    finally {
        reader.cancel().catch(() => undefined);
    }
    return text;
}
const asStringArray = (value, field) => {
    if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) {
        throw new DocumentRejected(`${field} must be an array of strings`);
    }
    return value;
};
/** Turn a validated document into the registration the server runs on. */
function toClient(clientId, doc, opts) {
    if (doc.client_id !== clientId) {
        throw new DocumentRejected("client_id in the document does not match its URL");
    }
    if ("client_secret" in doc || "client_secret_expires_at" in doc) {
        throw new DocumentRejected("a Client ID Metadata Document must not carry a client_secret");
    }
    const method = doc.token_endpoint_auth_method;
    if (method !== undefined && method !== "none") {
        throw new DocumentRejected(method === "private_key_jwt"
            ? "private_key_jwt is not allowed for a Client ID Metadata Document: its keys would come from the same document that names them"
            : `token_endpoint_auth_method ${JSON.stringify(method)} is not allowed for a Client ID Metadata Document`);
    }
    const redirectUris = asStringArray(doc.redirect_uris, "redirect_uris");
    if (redirectUris.length === 0)
        throw new DocumentRejected("redirect_uris must not be empty");
    for (const uri of redirectUris) {
        const rejection = checkRedirectUri(uri);
        if (rejection !== null) {
            throw new DocumentRejected(`redirect_uris entry ${JSON.stringify(uri)} is not acceptable: ${rejection}`);
        }
    }
    const grantTypes = doc.grant_types === undefined
        ? ["authorization_code"]
        : asStringArray(doc.grant_types, "grant_types");
    if (!grantTypes.includes("authorization_code")) {
        throw new DocumentRejected("grant_types must include authorization_code");
    }
    if (doc.response_types !== undefined) {
        if (!asStringArray(doc.response_types, "response_types").includes("code")) {
            throw new DocumentRejected("response_types must include code");
        }
    }
    // The consent page shows this, and a document client is by definition one
    // the deployment did not register: a blank name would put an unnamed
    // third party in front of the user.
    if (typeof doc.client_name !== "string" || doc.client_name.trim().length === 0) {
        throw new DocumentRejected("client_name is required and must be a non-empty string");
    }
    if (doc.client_uri !== undefined) {
        let uri = null;
        try {
            uri = typeof doc.client_uri === "string" ? new URL(doc.client_uri) : null;
        }
        catch {
            uri = null;
        }
        if (uri === null || uri.protocol !== "https:") {
            throw new DocumentRejected("client_uri must be an https URL");
        }
    }
    const claimedScopes = doc.scope === undefined
        ? undefined
        : typeof doc.scope === "string"
            ? doc.scope.split(" ").filter((s) => s.length > 0)
            : (() => {
                throw new DocumentRejected("scope must be a space-delimited string");
            })();
    const allowedScopes = claimedScopes === undefined
        ? [...opts.allowedScopes]
        : claimedScopes.filter((s) => opts.allowedScopes.includes(s));
    const name = typeof doc.client_name === "string" ? doc.client_name.trim().slice(0, 200) : "";
    const client = {
        clientId,
        tokenEndpointAuthMethod: "none",
        allowedRedirectUris: [...redirectUris],
        allowedScopes,
        allowedAudiences: [...opts.allowedAudiences],
        allowedGrantTypes: grantTypes.filter((g) => SUPPORTED_GRANT_TYPES.has(g)),
        firstParty: false,
        ...(name.length > 0 ? { clientName: name } : {}),
        ...(typeof doc.client_uri === "string" ? { clientUri: doc.client_uri } : {}),
    };
    documentClients.add(client);
    return client;
}
/**
 * The clients this module built from a document. A `WeakSet` rather than a
 * field on `PublicClient`: provenance is this server's fact, not something a
 * repository — or a document — can claim by setting a property.
 */
const documentClients = new WeakSet();
/**
 * Whether `client` was resolved from a Client ID Metadata Document, as opposed
 * to a pre-registered client whose id merely looks like a URL
 * (`withClientIdMetadataDocuments` answers those from the inner repository
 * first). For a document client, the host its `client_id` names is the one
 * fact about it this server verified; its `client_name` is the document
 * author's claim.
 */
export function isClientIdMetadataDocumentClient(client) {
    return client != null && documentClients.has(client);
}
export function createClientIdMetadataDocumentResolver(opts) {
    const fetchImpl = opts.fetch ?? fetch;
    const lookup = opts.lookup ??
        (async (hostname) => (await dns.lookup(hostname, { all: true, verbatim: true })).map((a) => a.address));
    const now = opts.now ?? Date.now;
    const maxBytes = opts.maxBytes ?? DEFAULT_CIMD_MAX_BYTES;
    const timeoutMs = opts.timeoutMs ?? DEFAULT_CIMD_TIMEOUT_MS;
    const cacheMaxAgeMs = opts.cacheMaxAgeMs ?? DEFAULT_CIMD_CACHE_MAX_AGE_MS;
    const logger = opts.logger;
    const maxCacheEntries = opts.maxCacheEntries ?? DEFAULT_CIMD_MAX_CACHE_ENTRIES;
    const staleIfErrorMs = opts.staleIfErrorMs ?? DEFAULT_CIMD_STALE_IF_ERROR_MS;
    const negativeCacheMs = opts.negativeCacheMs ?? DEFAULT_CIMD_NEGATIVE_CACHE_MS;
    const maxConcurrentFetches = opts.maxConcurrentFetches ?? DEFAULT_CIMD_MAX_CONCURRENT_FETCHES;
    /**
     * Refusals, bounded the same way documents are. An entry here means
     * `not a client`, with an expiry.
     */
    const refusals = new Map();
    /** Slots for an in-flight fetch; a waiter takes one when it is released. */
    let inFlightFetches = 0;
    const waiting = [];
    const withSlot = async (job) => {
        if (inFlightFetches >= maxConcurrentFetches) {
            await new Promise((resolve) => waiting.push(resolve));
        }
        inFlightFetches += 1;
        try {
            return await job();
        }
        finally {
            inFlightFetches -= 1;
            waiting.shift()?.();
        }
    };
    const cache = new Map();
    /**
     * Bounded, because an unauthenticated caller chooses the keys: every
     * distinct `client_id` URL that resolves to a valid document would
     * otherwise hold a `PublicClient` until it expired. Oldest insertion
     * first, as in the CRL and OCSP caches — the bound exists so the map
     * cannot grow without limit, not to maximise hits.
     */
    const remember = (clientId, entry) => {
        if (cache.size >= maxCacheEntries && !cache.has(clientId)) {
            const oldest = cache.keys().next();
            if (!oldest.done)
                cache.delete(oldest.value);
        }
        cache.set(clientId, entry);
    };
    /**
     * A refusal, remembered briefly and bounded the same way documents are —
     * the keys are the caller's here too, so a caller inventing ids must not be
     * able to grow this map without limit either.
     */
    const rememberRefusal = (clientId) => {
        if (refusals.size >= maxCacheEntries && !refusals.has(clientId)) {
            const oldest = refusals.keys().next();
            if (!oldest.done)
                refusals.delete(oldest.value);
        }
        refusals.set(clientId, now() + negativeCacheMs);
    };
    const inFlight = new Map();
    const hostAllowed = (hostname) => {
        if (hostMatches(opts.deniedHosts, hostname))
            return false;
        const allow = opts.allowedHosts ?? [];
        return allow.length === 0 || hostMatches(allow, hostname);
    };
    const fetchDocument = async (clientId, cached) => {
        const { hostname } = new URL(clientId);
        // The SSRF guard: every address the name resolves to must be public.
        const addresses = await lookup(hostname);
        if (addresses.length === 0)
            throw new DocumentRejected(`${hostname} resolves to nothing`);
        const special = addresses.find((a) => isSpecialUseAddress(a));
        if (special !== undefined) {
            throw new DocumentRejected(`${hostname} resolves to a special-use address (${special})`);
        }
        const res = await fetchImpl(clientId, {
            method: "GET",
            redirect: "manual",
            signal: AbortSignal.timeout(timeoutMs),
            headers: {
                accept: "application/json",
                ...(cached?.etag !== undefined ? { "if-none-match": cached.etag } : {}),
            },
        });
        if (res.status === 304 && cached !== undefined) {
            await res.body?.cancel().catch(() => undefined);
            return {
                client: cached.client,
                etag: cached.etag,
                cacheControl: res.headers.get("cache-control"),
            };
        }
        if (res.status !== 200) {
            await res.body?.cancel().catch(() => undefined);
            // A verdict on the document, or a verdict on the day the client's
            // server is having? A 4xx and a refused redirect say the
            // registration is not there or not one we will follow — the client's
            // own problem, and cached as a refusal. A 5xx or a 429 says their
            // server could not answer, which is exactly what `staleIfErrorMs`
            // exists to ride out; classifying it as a rejection would delete the
            // warm registration this server already validated and refuse a
            // working client for the length of someone else's outage.
            const transient = res.status >= 500 || res.status === 429;
            const message = `document fetch answered ${res.status}`;
            throw transient ? new Error(message) : new DocumentRejected(message);
        }
        const contentType = res.headers.get("content-type") ?? "";
        if (!/json/i.test(contentType)) {
            await res.body?.cancel().catch(() => undefined);
            throw new DocumentRejected(`document is not JSON (Content-Type: ${contentType || "absent"})`);
        }
        const text = await readCapped(res, maxBytes);
        let parsed;
        try {
            parsed = JSON.parse(text);
        }
        catch {
            throw new DocumentRejected("document is not valid JSON");
        }
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
            throw new DocumentRejected("document is not a JSON object");
        }
        return {
            client: toClient(clientId, parsed, opts),
            etag: res.headers.get("etag") ?? undefined,
            cacheControl: res.headers.get("cache-control"),
        };
    };
    const resolveUncached = async (clientId) => {
        const cached = cache.get(clientId);
        try {
            const { client, etag, cacheControl } = await withSlot(() => fetchDocument(clientId, cached));
            const granted = maxAgeMsOf(cacheControl);
            const ttl = Math.min(granted ?? cacheMaxAgeMs, cacheMaxAgeMs);
            if (ttl > 0) {
                remember(clientId, {
                    client,
                    etag,
                    expiresAt: now() + ttl,
                    staleDeadline: now() + ttl + staleIfErrorMs,
                });
            }
            else
                cache.delete(clientId);
            refusals.delete(clientId);
            return client;
        }
        catch (err) {
            const rejected = err instanceof DocumentRejected;
            logger?.warn({ clientId, reason: err instanceof Error ? err.message : String(err) }, rejected ? "cimd_document_rejected" : "cimd_document_fetch_failed");
            if (rejected) {
                // The document, not the network: this client stopped being a
                // client, so what was remembered of it goes now.
                cache.delete(clientId);
            }
            else if (cached !== undefined && staleIfErrorMs > 0) {
                // An outage is not a verdict on the client (#408). The
                // registration this server already validated is served for a
                // bounded window rather than breaking a working client because
                // someone else's server is down. `expiresAt` moves, so the window
                // does not renew itself indefinitely: the next revalidation is
                // attempted when it lapses, and only a success resets the clock.
                const staleUntil = Math.min(now() + staleIfErrorMs, cached.staleDeadline);
                if (staleUntil > now()) {
                    remember(clientId, { ...cached, expiresAt: staleUntil });
                    return cached.client;
                }
                cache.delete(clientId);
            }
            else {
                cache.delete(clientId);
            }
            if (negativeCacheMs > 0)
                rememberRefusal(clientId);
            return null;
        }
    };
    return {
        async resolve(clientId) {
            if (!isClientIdMetadataDocumentUrl(clientId))
                return null;
            if (!hostAllowed(new URL(clientId).hostname)) {
                logger?.warn({ clientId }, "cimd_host_not_allowed");
                return null;
            }
            const cached = cache.get(clientId);
            if (cached !== undefined && cached.expiresAt > now())
                return cached.client;
            const refusedUntil = refusals.get(clientId);
            if (refusedUntil !== undefined) {
                if (refusedUntil > now())
                    return null;
                refusals.delete(clientId);
            }
            const pending = inFlight.get(clientId);
            if (pending !== undefined)
                return pending;
            const job = resolveUncached(clientId).finally(() => inFlight.delete(clientId));
            inFlight.set(clientId, job);
            return job;
        },
    };
}
/**
 * A {@link ClientRepository} that answers pre-registered clients from `inner`
 * first and Client ID Metadata Documents second (#529). `authenticate` is
 * `inner`'s alone: a document never carries a secret.
 */
export function withClientIdMetadataDocuments(inner, opts) {
    const resolver = createClientIdMetadataDocumentResolver(opts);
    return {
        async findById(clientId) {
            const registered = await inner.findById(clientId);
            if (registered !== null)
                return registered;
            return resolver.resolve(clientId);
        },
        authenticate: (clientId, secret) => inner.authenticate(clientId, secret),
    };
}
