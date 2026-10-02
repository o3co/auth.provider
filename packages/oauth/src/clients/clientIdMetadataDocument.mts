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
 * Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document):
 * a client identifies itself with an `https` URL, and the JSON document at
 * that URL is its registration. This module fetches, validates and caches
 * such documents and returns a `PublicClient` (auth method `none`, PKCE S256,
 * never first-party, so consent always applies).
 *
 * Before any fetch: an id that is not a document URL, or whose host fails the
 * operator's `allowedHosts`/`deniedHosts`, is "not a client" (`null`), and
 * every address the host resolves to must be public (RFC 6890) — the draft's
 * SSRF guard. Rebinding between check and connect is a residual the draft
 * accepts; the host lists are the operator's lever against it.
 *
 * The fetch follows no redirects (the draft forbids it), has a timeout, caps
 * bytes on both `Content-Length` and the stream (a hostile host omits the
 * header), and accepts only `200` with JSON.
 *
 * `token_endpoint_auth_method` must be `none`: shared secrets are forbidden by
 * the draft, and `private_key_jwt` would take its keys from the same
 * attacker-authored document, authenticating the document, not the client.
 * Scopes are intersected with `allowedScopes`; audiences are the operator's
 * alone — a document says who the client is, never what it may reach. A
 * pre-registered client with the same id wins.
 *
 * The registered clients are read through core's client-record boundary, and
 * a document is resolved only when it answers that no client is registered
 * under the id (`absent`). A registration the boundary refuses is an unknown
 * client, never replaced by a document; a repository that cannot answer is an
 * outage, never answered from the document cache. A document client never
 * crosses the boundary: it is this module's own, built and validated here.
 */

import { promises as dns } from "node:dns";
import { isIP } from "node:net";
import {
	auditErrorText,
	type ClientRepository,
	checkRedirectUri,
	describeRedirectUriRejection,
	isLoopbackHostname,
	isSpecialUseAddress,
	type Logger,
	loggableError,
	type PublicClient,
	parseScopeTokens,
	validatedClientRepository,
} from "@o3co/auth-provider-core";

export interface ClientIdMetadataDocumentOptions {
	/** Scopes any such client may obtain — the ceiling its document's `scope` is intersected with. Empty admits none. */
	readonly allowedScopes: readonly string[];
	/** Audiences (resource servers) any such client may mint for. Empty admits only the client id. */
	readonly allowedAudiences: readonly string[];
	/** Hosts a document may live on: exact, or a `.suffix` for a domain and its subdomains. Empty admits any public host. */
	readonly allowedHosts?: readonly string[];
	/** Hosts refused even when allowed above; same forms. */
	readonly deniedHosts?: readonly string[];
	/** Byte cap on the document. Default 5120, the draft's recommendation. */
	readonly maxBytes?: number;
	/** Fetch timeout. Default 5000 ms. */
	readonly timeoutMs?: number;
	/** Upper bound on how long a valid document is served from cache. Default 10 minutes. */
	readonly cacheMaxAgeMs?: number;
	/** Bound on remembered documents. Default {@link DEFAULT_CIMD_MAX_CACHE_ENTRIES}. */
	readonly maxCacheEntries?: number;
	/**
	 * How long a cached registration may still be served after a
	 * revalidation that failed for a reason that is not the document's.
	 * Default {@link DEFAULT_CIMD_STALE_IF_ERROR_MS}. Zero disables it.
	 */
	readonly staleIfErrorMs?: number;
	/**
	 * How long a refusal is remembered, so the same id is not fetched again
	 * on every request. Default {@link DEFAULT_CIMD_NEGATIVE_CACHE_MS}.
	 */
	readonly negativeCacheMs?: number;
	/**
	 * How many documents may be in flight at once, across every client id.
	 * Default {@link DEFAULT_CIMD_MAX_CONCURRENT_FETCHES}.
	 */
	readonly maxConcurrentFetches?: number;
	readonly logger?: Logger;
	/** Test seams. */
	readonly fetch?: typeof fetch;
	readonly lookup?: (hostname: string) => Promise<readonly string[]>;
	readonly now?: () => number;
}

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
const SUPPORTED_GRANT_TYPES: ReadonlySet<string> = new Set(["authorization_code", "refresh_token"]);

/**
 * Whether `clientId` has the shape of a Client ID Metadata Document URL
 * (draft §3.1): `https`, a path, no fragment, no credentials, no dot segments,
 * no query string, and a host that is a name rather than an address.
 *
 * Shape only — the host policy and the resolution check are the resolver's.
 * Exported so `/authorize` and the token endpoint can tell "not a client at
 * all" from "a document URL we could not honour" in their logs.
 */
export function isClientIdMetadataDocumentUrl(clientId: string): boolean {
	let url: URL;
	try {
		url = new URL(clientId);
	} catch {
		return false;
	}
	if (url.protocol !== "https:") return false;
	if (url.href !== clientId) return false; // not in canonical form: the document's client_id could never equal it
	if (url.pathname === "" || url.pathname === "/") return false;
	if (url.hash !== "" || clientId.endsWith("#")) return false;
	if (url.username !== "" || url.password !== "") return false;
	if (url.search !== "" || clientId.endsWith("?")) return false;
	if (url.pathname.split("/").some((segment) => segment === "." || segment === "..")) return false;
	if (isIP(url.hostname) !== 0 || url.hostname.startsWith("[")) return false;
	// A trailing dot (the DNS root) survives canonicalisation and reaches the
	// same host, but the host policy compares strings, so `deniedHosts` would
	// fail open. Refused rather than normalised: a document must echo its
	// client id exactly.
	if (url.hostname.endsWith(".")) return false;
	if (isLoopbackHostname(url.hostname)) return false;
	return true;
}

const hostMatches = (patterns: readonly string[] | undefined, hostname: string): boolean =>
	(patterns ?? []).some((pattern) => {
		const p = pattern.toLowerCase();
		const h = hostname.toLowerCase();
		return p.startsWith(".") ? h === p.slice(1) || h.endsWith(p) : h === p;
	});

/**
 * How long a cached registration outlives a revalidation that failed for a
 * reason that is not the document's (DNS, 5xx, timeout): an outage at the
 * client's host is not a verdict on the client. A rejected document is
 * evicted immediately.
 */
export const DEFAULT_CIMD_STALE_IF_ERROR_MS = 5 * 60 * 1000;

/**
 * How long a refusal is remembered. Without it, every distinct URL-shaped
 * `client_id` costs a DNS lookup, TLS handshake and GET per request, which an
 * unauthenticated caller can aim at a tarpit or a third party. Short, so a
 * client that fixes its document is not locked out for long.
 */
export const DEFAULT_CIMD_NEGATIVE_CACHE_MS = 60 * 1000;

/**
 * How many documents may be fetched at once across every client id, so the
 * outbound cost of unauthenticated requests is bounded however many ids a
 * caller invents.
 */
export const DEFAULT_CIMD_MAX_CONCURRENT_FETCHES = 8;

interface CacheEntry {
	readonly client: PublicClient;
	readonly etag: string | undefined;
	readonly expiresAt: number;
	/**
	 * The instant past which this registration is not served at all, however
	 * long the outage lasts — one stale window from when it was last
	 * successfully fetched, not one per failed revalidation.
	 */
	readonly staleDeadline: number;
}

/**
 * The `max-age` a `Cache-Control` header grants, or `undefined` when it grants
 * none (`no-store`, `no-cache`, or absent). `private` is fine: this server is
 * the one client of the document.
 */
const maxAgeMsOf = (cacheControl: string | null): number | undefined => {
	if (cacheControl === null) return undefined;
	const directives = cacheControl.split(",").map((d) => d.trim().toLowerCase());
	if (directives.includes("no-store") || directives.includes("no-cache")) return 0;
	const maxAge = directives.find((d) => d.startsWith("max-age="));
	if (maxAge === undefined) return undefined;
	const seconds = Number(maxAge.slice("max-age=".length));
	return Number.isFinite(seconds) && seconds >= 0 ? seconds * 1000 : undefined;
};

class DocumentRejected extends Error {}

/** Read at most `limit` bytes of `res`; throw past it, header or stream. */
async function readCapped(res: Response, limit: number): Promise<string> {
	const declared = Number(res.headers.get("content-length"));
	if (Number.isFinite(declared) && declared > limit) {
		await res.body?.cancel().catch(() => undefined);
		throw new DocumentRejected(`document exceeds ${limit} bytes (Content-Length: ${declared})`);
	}
	if (res.body === null) return "";
	const reader = res.body.getReader();
	const decoder = new TextDecoder();
	let text = "";
	let read = 0;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			read += value.byteLength;
			if (read > limit) throw new DocumentRejected(`document exceeds ${limit} bytes`);
			text += decoder.decode(value, { stream: true });
		}
	} finally {
		reader.cancel().catch(() => undefined);
	}
	return text;
}

const asStringArray = (value: unknown, field: string): readonly string[] => {
	if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) {
		throw new DocumentRejected(`${field} must be an array of strings`);
	}
	return value as readonly string[];
};

/** Turn a validated document into the registration the server runs on. */
function toClient(
	clientId: string,
	doc: Record<string, unknown>,
	opts: ClientIdMetadataDocumentOptions,
): PublicClient {
	if (doc.client_id !== clientId) {
		throw new DocumentRejected("client_id in the document does not match its URL");
	}
	if ("client_secret" in doc || "client_secret_expires_at" in doc) {
		throw new DocumentRejected("a Client ID Metadata Document must not carry a client_secret");
	}
	const method = doc.token_endpoint_auth_method;
	if (method !== undefined && method !== "none") {
		throw new DocumentRejected(
			method === "private_key_jwt"
				? "private_key_jwt is not allowed for a Client ID Metadata Document: its keys would come from the same document that names them"
				: // The document's author wrote it: quoted as the Content-Type is.
					`token_endpoint_auth_method '${auditErrorText(typeof method === "string" ? method : JSON.stringify(method))}' is not allowed for a Client ID Metadata Document`,
		);
	}
	const redirectUris = asStringArray(doc.redirect_uris, "redirect_uris");
	if (redirectUris.length === 0) throw new DocumentRejected("redirect_uris must not be empty");
	for (const uri of redirectUris) {
		const rejection = checkRedirectUri(uri);
		if (rejection !== null) {
			throw new DocumentRejected(
				`redirect_uris entry '${auditErrorText(uri)}' is not acceptable: ${describeRedirectUriRejection(rejection)}`,
			);
		}
	}
	const grantTypes =
		doc.grant_types === undefined
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
		let uri: URL | null = null;
		try {
			uri = typeof doc.client_uri === "string" ? new URL(doc.client_uri) : null;
		} catch {
			uri = null;
		}
		if (uri === null || uri.protocol !== "https:") {
			throw new DocumentRejected("client_uri must be an https URL");
		}
	}
	// RFC 7591 §2 `scope`, by RFC 6749 §3.3's grammar. A third party's
	// document is read tolerantly (`parseScopeTokens`), as an upstream's answer
	// is: what it names is intersected with the operator's ceiling below, so a
	// scope it names but spells with a tab is not lost, and one that names no
	// scope-token claims nothing rather than reading as absent.
	const claimedScopes =
		doc.scope === undefined
			? undefined
			: typeof doc.scope === "string"
				? parseScopeTokens(doc.scope)
				: (() => {
						throw new DocumentRejected("scope must be a space-delimited string");
					})();
	const allowedScopes =
		claimedScopes === undefined
			? [...opts.allowedScopes]
			: claimedScopes.filter((s) => opts.allowedScopes.includes(s));
	const name = typeof doc.client_name === "string" ? doc.client_name.trim().slice(0, 200) : "";

	const client: PublicClient = {
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
const documentClients = new WeakSet<PublicClient>();

/**
 * Whether `client` was resolved from a Client ID Metadata Document, as opposed
 * to a pre-registered client whose id merely looks like a URL
 * (`withClientIdMetadataDocuments` answers those from the inner repository
 * first). For a document client, the host its `client_id` names is the one
 * fact about it this server verified; its `client_name` is the document
 * author's claim.
 */
export function isClientIdMetadataDocumentClient(client: PublicClient | null | undefined): boolean {
	return client != null && documentClients.has(client);
}

export interface ClientIdMetadataDocumentResolver {
	/** The registration the document at `clientId` describes, or `null` when there is none to honour. */
	resolve(clientId: string): Promise<PublicClient | null>;
}

export function createClientIdMetadataDocumentResolver(
	opts: ClientIdMetadataDocumentOptions,
): ClientIdMetadataDocumentResolver {
	const fetchImpl = opts.fetch ?? fetch;
	const lookup =
		opts.lookup ??
		(async (hostname: string) =>
			(await dns.lookup(hostname, { all: true, verbatim: true })).map((a) => a.address));
	const now = opts.now ?? Date.now;
	const maxBytes = opts.maxBytes ?? DEFAULT_CIMD_MAX_BYTES;
	const timeoutMs = opts.timeoutMs ?? DEFAULT_CIMD_TIMEOUT_MS;
	const cacheMaxAgeMs = opts.cacheMaxAgeMs ?? DEFAULT_CIMD_CACHE_MAX_AGE_MS;
	const logger = opts.logger;
	const maxCacheEntries = opts.maxCacheEntries ?? DEFAULT_CIMD_MAX_CACHE_ENTRIES;
	const staleIfErrorMs = opts.staleIfErrorMs ?? DEFAULT_CIMD_STALE_IF_ERROR_MS;
	const negativeCacheMs = opts.negativeCacheMs ?? DEFAULT_CIMD_NEGATIVE_CACHE_MS;
	const maxConcurrentFetches = opts.maxConcurrentFetches ?? DEFAULT_CIMD_MAX_CONCURRENT_FETCHES;
	/** Refused client ids, with the instant each refusal expires. */
	const refusals = new Map<string, number>();
	/** Slots for an in-flight fetch; a waiter takes one when it is released. */
	let inFlightFetches = 0;
	const waiting: Array<() => void> = [];
	const withSlot = async <T,>(job: () => Promise<T>): Promise<T> => {
		if (inFlightFetches >= maxConcurrentFetches) {
			await new Promise<void>((resolve) => waiting.push(resolve));
		}
		inFlightFetches += 1;
		try {
			return await job();
		} finally {
			inFlightFetches -= 1;
			waiting.shift()?.();
		}
	};
	const cache = new Map<string, CacheEntry>();
	/**
	 * Bounded because an unauthenticated caller chooses the keys. Evicts the
	 * oldest insertion: the bound caps memory, it does not maximise hits.
	 */
	const remember = (clientId: string, entry: CacheEntry): void => {
		if (cache.size >= maxCacheEntries && !cache.has(clientId)) {
			const oldest = cache.keys().next();
			if (!oldest.done) cache.delete(oldest.value);
		}
		cache.set(clientId, entry);
	};

	/** A refusal, bounded like the document cache: the caller chooses these keys too. */
	const rememberRefusal = (clientId: string): void => {
		if (refusals.size >= maxCacheEntries && !refusals.has(clientId)) {
			const oldest = refusals.keys().next();
			if (!oldest.done) refusals.delete(oldest.value);
		}
		refusals.set(clientId, now() + negativeCacheMs);
	};
	const inFlight = new Map<string, Promise<PublicClient | null>>();

	const hostAllowed = (hostname: string): boolean => {
		if (hostMatches(opts.deniedHosts, hostname)) return false;
		const allow = opts.allowedHosts ?? [];
		return allow.length === 0 || hostMatches(allow, hostname);
	};

	const fetchDocument = async (clientId: string, cached: CacheEntry | undefined) => {
		const { hostname } = new URL(clientId);
		// The SSRF guard: every address the name resolves to must be public.
		const addresses = await lookup(hostname);
		if (addresses.length === 0) throw new DocumentRejected(`${hostname} resolves to nothing`);
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
			// A 4xx or refused redirect is a verdict on the document (a refusal);
			// a 5xx or 429 is the client's server failing to answer, which
			// `staleIfErrorMs` rides out instead of evicting a validated registration.
			const transient = res.status >= 500 || res.status === 429;
			const message = `document fetch answered ${res.status}`;
			throw transient ? new Error(message) : new DocumentRejected(message);
		}
		const contentType = res.headers.get("content-type") ?? "";
		if (!/json/i.test(contentType)) {
			await res.body?.cancel().catch(() => undefined);
			// The client's server wrote the header: quoted sanitised and capped,
			// since the message is what the log keeps as `reason`.
			throw new DocumentRejected(
				`document is not JSON (Content-Type: ${contentType === "" ? "absent" : auditErrorText(contentType)})`,
			);
		}
		const text = await readCapped(res, maxBytes);
		let parsed: unknown;
		try {
			parsed = JSON.parse(text);
		} catch {
			throw new DocumentRejected("document is not valid JSON");
		}
		if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
			throw new DocumentRejected("document is not a JSON object");
		}
		return {
			client: toClient(clientId, parsed as Record<string, unknown>, opts),
			etag: res.headers.get("etag") ?? undefined,
			cacheControl: res.headers.get("cache-control"),
		};
	};

	const resolveUncached = async (clientId: string): Promise<PublicClient | null> => {
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
			} else cache.delete(clientId);
			refusals.delete(clientId);
			return client;
		} catch (err) {
			const rejected = err instanceof DocumentRejected;
			// The rejection's own text, or a fetch failure's projection: never a
			// thrown value as it came (loggableError). `err` beside it carries
			// what `reason` cannot — a fetch failure's cause code.
			const projected = loggableError(err);
			logger?.warn(
				{
					clientId: auditErrorText(clientId),
					reason: projected.detail ?? projected.name,
					err: projected,
				},
				rejected ? "cimd_document_rejected" : "cimd_document_fetch_failed",
			);
			if (rejected) {
				// The document, not the network: this client stopped being a
				// client, so what was remembered of it goes now.
				cache.delete(clientId);
			} else if (cached !== undefined && staleIfErrorMs > 0) {
				// An outage is not a verdict on the client: serve the validated
				// registration for a bounded window. `expiresAt` moves so the next
				// request retries; only a success extends `staleDeadline`.
				const staleUntil = Math.min(now() + staleIfErrorMs, cached.staleDeadline);
				if (staleUntil > now()) {
					remember(clientId, { ...cached, expiresAt: staleUntil });
					return cached.client;
				}
				cache.delete(clientId);
			} else {
				cache.delete(clientId);
			}
			if (negativeCacheMs > 0) rememberRefusal(clientId);
			return null;
		}
	};

	return {
		async resolve(clientId) {
			if (!isClientIdMetadataDocumentUrl(clientId)) return null;
			if (!hostAllowed(new URL(clientId).hostname)) {
				logger?.warn({ clientId: auditErrorText(clientId) }, "cimd_host_not_allowed");
				return null;
			}
			const cached = cache.get(clientId);
			if (cached !== undefined && cached.expiresAt > now()) return cached.client;
			const refusedUntil = refusals.get(clientId);
			if (refusedUntil !== undefined) {
				if (refusedUntil > now()) return null;
				refusals.delete(clientId);
			}
			const pending = inFlight.get(clientId);
			if (pending !== undefined) return pending;
			const job = resolveUncached(clientId).finally(() => inFlight.delete(clientId));
			inFlight.set(clientId, job);
			return job;
		},
	};
}

/** The repositories {@link withClientIdMetadataDocuments} built: each the one document fallback of its composition. */
const documentFallbacks = new WeakSet<ClientRepository>();

/**
 * A {@link ClientRepository} that answers pre-registered clients from `inner`
 * first and Client ID Metadata Documents second.
 *
 * `inner` is read through core's client-record boundary
 * (`validatedClientRepository`, a no-op when it already is one), which says
 * per id whether a client is registered (`found`), registered but refused
 * (`refused`) or not registered (`absent`). That answer comes first, on every
 * lookup, before the document cache or the refusal memo is consulted:
 *
 * - `found`: the registered client, validated.
 * - `refused`: no client. The document is never resolved in its place, so a
 *   malformed registration cannot be replaced by whatever the URL serves.
 * - `absent`: the document, resolved as {@link createClientIdMetadataDocumentResolver} does.
 * - A throw is the repository's outage and is let through, never answered
 *   from the document cache or its stale window.
 *
 * `authenticate` is `inner`'s alone, through the boundary: a document never
 * carries a secret.
 *
 * One fallback per composition: `inner` that is already such a repository is
 * refused with a `TypeError`. Its own lookup answers a refusal `null`, so a
 * second fallback over it would read the refusal as an absence.
 *
 * Interim composition rule, until core installs its boundary in the
 * `clientRepository` slot: the boundary is the outermost layer over the
 * registered clients, this fallback is the only one and is never wrapped,
 * and one copy of core and of this package is loaded. A fallback is
 * recognised by object identity, so a forwarder over one, or a fallback or
 * boundary from another loaded copy, would read a refusal as an absence.
 */
export function withClientIdMetadataDocuments(
	inner: ClientRepository,
	opts: ClientIdMetadataDocumentOptions,
): ClientRepository {
	if (documentFallbacks.has(inner)) {
		throw new TypeError(
			"withClientIdMetadataDocuments: the repository already resolves Client ID Metadata Documents; " +
				"a composition has one such fallback, over its registered clients",
		);
	}
	const registered = validatedClientRepository(
		inner,
		opts.logger === undefined ? {} : { logger: opts.logger },
	);
	const resolver = createClientIdMetadataDocumentResolver(opts);
	const fallback: ClientRepository = {
		async findById(clientId) {
			const lookup = await registered.lookupClient(clientId);
			switch (lookup.outcome) {
				case "found":
					return lookup.client;
				case "refused":
					return null;
				case "absent":
					return resolver.resolve(clientId);
			}
		},
		authenticate: (clientId, secret) => registered.authenticate(clientId, secret),
	};
	documentFallbacks.add(fallback);
	return fallback;
}
