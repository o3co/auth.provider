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
 * `private_key_jwt` is refused until this server authenticates clients that
 * way (#484); `client_secret` must be absent; `grant_types` must include
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
import {
	type ClientRepository,
	checkRedirectUri,
	isLoopbackHostname,
	isSpecialUseAddress,
	type Logger,
	type PublicClient,
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
	readonly logger?: Logger;
	/** Test seams. */
	readonly fetch?: typeof fetch;
	readonly lookup?: (hostname: string) => Promise<readonly string[]>;
	readonly now?: () => number;
}

export const DEFAULT_CIMD_MAX_BYTES = 5 * 1024;
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
	if (isLoopbackHostname(url.hostname)) return false;
	return true;
}

const hostMatches = (patterns: readonly string[] | undefined, hostname: string): boolean =>
	(patterns ?? []).some((pattern) => {
		const p = pattern.toLowerCase();
		const h = hostname.toLowerCase();
		return p.startsWith(".") ? h === p.slice(1) || h.endsWith(p) : h === p;
	});

interface CacheEntry {
	readonly client: PublicClient;
	readonly etag: string | undefined;
	readonly expiresAt: number;
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
				? "private_key_jwt client authentication is not supported yet (#484)"
				: `token_endpoint_auth_method ${JSON.stringify(method)} is not allowed for a Client ID Metadata Document`,
		);
	}
	const redirectUris = asStringArray(doc.redirect_uris, "redirect_uris");
	if (redirectUris.length === 0) throw new DocumentRejected("redirect_uris must not be empty");
	for (const uri of redirectUris) {
		const rejection = checkRedirectUri(uri);
		if (rejection !== null) {
			throw new DocumentRejected(
				`redirect_uris entry ${JSON.stringify(uri)} is not acceptable: ${rejection}`,
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
	if (doc.client_name !== undefined && typeof doc.client_name !== "string") {
		throw new DocumentRejected("client_name must be a string");
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
	const claimedScopes =
		doc.scope === undefined
			? undefined
			: typeof doc.scope === "string"
				? doc.scope.split(" ").filter((s) => s.length > 0)
				: (() => {
						throw new DocumentRejected("scope must be a space-delimited string");
					})();
	const allowedScopes =
		claimedScopes === undefined
			? [...opts.allowedScopes]
			: claimedScopes.filter((s) => opts.allowedScopes.includes(s));
	const name = typeof doc.client_name === "string" ? doc.client_name.trim().slice(0, 200) : "";

	return {
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
	const cache = new Map<string, CacheEntry>();
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
			throw new DocumentRejected(`document fetch answered ${res.status}`);
		}
		const contentType = res.headers.get("content-type") ?? "";
		if (!/json/i.test(contentType)) {
			await res.body?.cancel().catch(() => undefined);
			throw new DocumentRejected(`document is not JSON (Content-Type: ${contentType || "absent"})`);
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
			const { client, etag, cacheControl } = await fetchDocument(clientId, cached);
			const granted = maxAgeMsOf(cacheControl);
			const ttl = Math.min(granted ?? cacheMaxAgeMs, cacheMaxAgeMs);
			if (ttl > 0) cache.set(clientId, { client, etag, expiresAt: now() + ttl });
			else cache.delete(clientId);
			return client;
		} catch (err) {
			// Never cached, and never a 5xx: a client whose document cannot be
			// honoured is, to this server, a client that does not exist.
			cache.delete(clientId);
			logger?.warn(
				{ clientId, reason: err instanceof Error ? err.message : String(err) },
				err instanceof DocumentRejected ? "cimd_document_rejected" : "cimd_document_fetch_failed",
			);
			return null;
		}
	};

	return {
		async resolve(clientId) {
			if (!isClientIdMetadataDocumentUrl(clientId)) return null;
			if (!hostAllowed(new URL(clientId).hostname)) {
				logger?.warn({ clientId }, "cimd_host_not_allowed");
				return null;
			}
			const cached = cache.get(clientId);
			if (cached !== undefined && cached.expiresAt > now()) return cached.client;
			const pending = inFlight.get(clientId);
			if (pending !== undefined) return pending;
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
export function withClientIdMetadataDocuments(
	inner: ClientRepository,
	opts: ClientIdMetadataDocumentOptions,
): ClientRepository {
	const resolver = createClientIdMetadataDocumentResolver(opts);
	return {
		async findById(clientId) {
			const registered = await inner.findById(clientId);
			if (registered !== null) return registered;
			return resolver.resolve(clientId);
		},
		authenticate: (clientId, secret) => inner.authenticate(clientId, secret),
	};
}
