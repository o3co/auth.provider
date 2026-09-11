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
 * #529 — Client ID Metadata Documents: a client whose `client_id` is the
 * `https` URL of its own registration. Almost every case is a refusal, and
 * the ones that are not pin what the fetched document turns into. No network:
 * `fetch` and `lookup` are the resolver's seams.
 */

import type { ClientRepository, Logger } from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import {
	type ClientIdMetadataDocumentOptions,
	createClientIdMetadataDocumentResolver,
	DEFAULT_CIMD_MAX_BYTES,
	isClientIdMetadataDocumentUrl,
	withClientIdMetadataDocuments,
} from "#/clients/clientIdMetadataDocument.mjs";

const CLIENT_URL = "https://client.example/oauth/client-metadata.json";

const document = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
	client_id: CLIENT_URL,
	client_name: "Acme Chat",
	client_uri: "https://client.example",
	redirect_uris: ["https://client.example/cb", "http://127.0.0.1/cb"],
	grant_types: ["authorization_code", "refresh_token"],
	response_types: ["code"],
	scope: "read write admin",
	token_endpoint_auth_method: "none",
	...over,
});

type FetchCall = { url: string; init: RequestInit | undefined };

/** A fake `fetch` answering one canned response per call, recording what it was asked. */
const fakeFetch = (
	responses: Array<() => Response>,
): { fetch: typeof fetch; calls: FetchCall[] } => {
	const calls: FetchCall[] = [];
	const impl = (async (input: string | URL | Request, init?: RequestInit) => {
		calls.push({ url: String(input), init });
		const next = responses.shift();
		if (next === undefined) throw new Error("fakeFetch: no response queued");
		return next();
	}) as typeof fetch;
	return { fetch: impl, calls };
};

const json = (body: unknown, headers: Record<string, string> = {}, status = 200): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json", ...headers },
	});

const publicLookup = async () => ["93.184.216.34"];

const resolver = (
	over: Partial<ClientIdMetadataDocumentOptions> = {},
	responses: Array<() => Response> = [() => json(document())],
) => {
	const { fetch, calls } = fakeFetch(responses);
	const warn = vi.fn();
	const logger = { warn, info: vi.fn(), error: vi.fn(), debug: vi.fn() } as unknown as Logger;
	const r = createClientIdMetadataDocumentResolver({
		allowedScopes: ["read", "write"],
		allowedAudiences: ["https://mcp.example"],
		fetch,
		lookup: publicLookup,
		logger,
		...over,
	});
	return { resolve: (id = CLIENT_URL) => r.resolve(id), calls, warn };
};

describe("isClientIdMetadataDocumentUrl (draft §3.1, #529)", () => {
	it("accepts an https URL with a path, in canonical form", () => {
		expect(isClientIdMetadataDocumentUrl(CLIENT_URL)).toBe(true);
		expect(isClientIdMetadataDocumentUrl("https://client.example:8443/meta")).toBe(true);
	});

	it("refuses everything that is not one", () => {
		for (const id of [
			"mobile-app", // a plain identifier
			"http://client.example/meta", // not https
			"https://client.example", // no path
			"https://client.example/", // no path
			"https://client.example/meta#frag", // fragment
			"https://client.example/meta#", // empty fragment
			"https://user:pw@client.example/meta", // credentials
			"https://client.example/a/../meta", // dot segment
			"https://client.example/./meta",
			"https://client.example/meta?x=1", // query string
			"https://client.example/meta?",
			"https://93.184.216.34/meta", // IP literal
			"https://[2606:4700::1]/meta",
			"https://localhost/meta", // loopback name
			"https://127.0.0.1/meta",
			"https://CLIENT.example/Meta", // not canonical: the document's client_id could never equal it
			"not a url",
			"",
		]) {
			expect(isClientIdMetadataDocumentUrl(id), id).toBe(false);
		}
	});
});

describe("createClientIdMetadataDocumentResolver — what a document becomes (#529)", () => {
	it("turns a valid document into a public, non-first-party registration under the operator's ceilings", async () => {
		const { resolve, calls } = resolver();
		const client = await resolve();
		expect(client).toEqual({
			clientId: CLIENT_URL,
			tokenEndpointAuthMethod: "none",
			allowedRedirectUris: ["https://client.example/cb", "http://127.0.0.1/cb"],
			// `admin` is in the document; the operator's ceiling does not admit it.
			allowedScopes: ["read", "write"],
			allowedAudiences: ["https://mcp.example"],
			allowedGrantTypes: ["authorization_code", "refresh_token"],
			firstParty: false,
			clientName: "Acme Chat",
			clientUri: "https://client.example",
		});
		expect(calls).toHaveLength(1);
		expect(calls[0]?.url).toBe(CLIENT_URL);
		expect(calls[0]?.init).toMatchObject({ method: "GET", redirect: "manual" });
		const headers = (calls[0]?.init?.headers ?? {}) as Record<string, string>;
		expect(headers.accept).toBe("application/json");
	});

	it("takes the operator's whole scope ceiling when the document names no scope, and drops grant types it does not support", async () => {
		const { resolve } = resolver({}, [
			() => json(document({ scope: undefined, grant_types: ["authorization_code", "implicit"] })),
		]);
		const client = await resolve();
		expect(client?.allowedScopes).toEqual(["read", "write"]);
		expect(client?.allowedGrantTypes).toEqual(["authorization_code"]);
	});

	it("is not a client at all when the id is not a document URL, without fetching", async () => {
		const { resolve, calls } = resolver();
		expect(await resolve("mobile-app")).toBeNull();
		expect(await resolve("http://client.example/meta")).toBeNull();
		expect(calls).toHaveLength(0);
	});
});

describe("createClientIdMetadataDocumentResolver — the SSRF guard and the host policy (#529)", () => {
	it("refuses a host that resolves to a special-use address, before any fetch", async () => {
		for (const address of [
			"127.0.0.1",
			"10.0.0.5",
			"169.254.169.254",
			"::1",
			"::ffff:192.168.0.1",
		]) {
			const { resolve, calls, warn } = resolver({ lookup: async () => ["93.184.216.34", address] });
			expect(await resolve(), address).toBeNull();
			expect(calls).toHaveLength(0);
			expect(warn).toHaveBeenCalledWith(
				expect.objectContaining({ reason: expect.stringContaining("special-use") }),
				"cimd_document_rejected",
			);
		}
	});

	it("refuses a name that does not resolve, or whose lookup fails, without fetching", async () => {
		const empty = resolver({ lookup: async () => [] });
		expect(await empty.resolve()).toBeNull();
		expect(empty.calls).toHaveLength(0);
		const failing = resolver({
			lookup: async () => {
				throw new Error("ENOTFOUND");
			},
		});
		expect(await failing.resolve()).toBeNull();
		expect(failing.calls).toHaveLength(0);
		expect(failing.warn).toHaveBeenCalledWith(expect.anything(), "cimd_document_fetch_failed");
	});

	it("honours allowedHosts (exact or .suffix) and deniedHosts, deny winning", async () => {
		expect(await resolver({ allowedHosts: ["other.example"] }).resolve()).toBeNull();
		expect(await resolver({ allowedHosts: ["client.example"] }).resolve()).not.toBeNull();
		expect(await resolver({ allowedHosts: [".example"] }).resolve()).not.toBeNull();
		expect(
			await resolver({ allowedHosts: [".example"], deniedHosts: ["client.example"] }).resolve(),
		).toBeNull();
		expect(await resolver({ deniedHosts: [".example"] }).resolve()).toBeNull();
		const { resolve, calls, warn } = resolver({ allowedHosts: ["other.example"] });
		await resolve();
		expect(calls).toHaveLength(0);
		expect(warn).toHaveBeenCalledWith(expect.anything(), "cimd_host_not_allowed");
	});
});

describe("createClientIdMetadataDocumentResolver — the fetch (#529)", () => {
	it("refuses a redirect, a non-200, and a non-JSON body", async () => {
		for (const [name, response] of [
			[
				"redirect",
				() => new Response(null, { status: 302, headers: { location: "https://elsewhere" } }),
			],
			["404", () => json({}, {}, 404)],
			["500", () => json({}, {}, 500)],
			[
				"html",
				() => new Response("<html/>", { status: 200, headers: { "content-type": "text/html" } }),
			],
			[
				"broken json",
				() => new Response("{", { status: 200, headers: { "content-type": "application/json" } }),
			],
			["array", () => json([])],
		] as const) {
			const { resolve, warn } = resolver({}, [response]);
			expect(await resolve(), name).toBeNull();
			expect(warn, name).toHaveBeenCalledWith(expect.anything(), "cimd_document_rejected");
		}
	});

	it("caps the document at maxBytes, by Content-Length and by what actually arrives", async () => {
		const big = JSON.stringify(document({ client_name: "x".repeat(DEFAULT_CIMD_MAX_BYTES) }));
		const declared = resolver({}, [
			() =>
				new Response(big, {
					status: 200,
					headers: { "content-type": "application/json", "content-length": String(big.length) },
				}),
		]);
		expect(await declared.resolve()).toBeNull();
		// No Content-Length: the stream is what stops it.
		const streamed = resolver({}, [
			() => new Response(big, { status: 200, headers: { "content-type": "application/json" } }),
		]);
		expect(await streamed.resolve()).toBeNull();
		expect(streamed.warn).toHaveBeenCalledWith(
			expect.objectContaining({ reason: expect.stringContaining("exceeds") }),
			"cimd_document_rejected",
		);
		// A small cap can be raised by the operator.
		const roomy = resolver({ maxBytes: big.length + 1 }, [() => json(JSON.parse(big))]);
		expect(await roomy.resolve()).not.toBeNull();
	});

	it("treats a fetch that throws (timeout, network) as no client, logged as a fetch failure", async () => {
		const { resolve, warn } = resolver({}, [
			() => {
				throw new Error("TimeoutError");
			},
		]);
		expect(await resolve()).toBeNull();
		expect(warn).toHaveBeenCalledWith(expect.anything(), "cimd_document_fetch_failed");
	});
});

describe("createClientIdMetadataDocumentResolver — the document (#529)", () => {
	const refuses = async (name: string, over: Record<string, unknown>, reason: RegExp) => {
		const { resolve, warn } = resolver({}, [() => json(document(over))]);
		expect(await resolve(), name).toBeNull();
		expect(warn, name).toHaveBeenCalledWith(
			expect.objectContaining({ reason: expect.stringMatching(reason) }),
			"cimd_document_rejected",
		);
	};

	it("requires client_id to equal the URL by simple string comparison", async () => {
		await refuses("other id", { client_id: "https://client.example/other.json" }, /client_id/);
		await refuses("missing id", { client_id: undefined }, /client_id/);
	});

	it("requires redirect_uris, non-empty, each one this server would register", async () => {
		await refuses("missing", { redirect_uris: undefined }, /redirect_uris/);
		await refuses("empty", { redirect_uris: [] }, /redirect_uris/);
		await refuses("not strings", { redirect_uris: [1] }, /redirect_uris/);
		await refuses(
			"fragment",
			{ redirect_uris: ["https://client.example/cb#x"] },
			/redirect_uris entry/,
		);
		await refuses(
			"plain http",
			{ redirect_uris: ["http://client.example/cb"] },
			/redirect_uris entry/,
		);
	});

	it("refuses a shared-secret method, a client_secret, and private_key_jwt until #484", async () => {
		await refuses("basic", { token_endpoint_auth_method: "client_secret_basic" }, /not allowed/);
		await refuses("secret", { client_secret: "s" }, /client_secret/);
		await refuses(
			"pkjwt",
			{ token_endpoint_auth_method: "private_key_jwt", jwks_uri: "https://client.example/jwks" },
			/private_key_jwt/,
		);
	});

	it("requires the authorization-code flow", async () => {
		await refuses("no code grant", { grant_types: ["client_credentials"] }, /authorization_code/);
		await refuses("no code response", { response_types: ["token"] }, /response_types/);
	});

	it("checks the shapes of what the consent page will show", async () => {
		await refuses("client_name", { client_name: 42 }, /client_name/);
		// #529 review: the consent page shows this, and a document client is by
		// definition one the deployment never registered.
		await refuses("client_name absent", { client_name: undefined }, /client_name/);
		await refuses("client_name blank", { client_name: "   " }, /client_name/);
		await refuses("client_uri http", { client_uri: "http://client.example" }, /client_uri/);
		await refuses("client_uri junk", { client_uri: "nope" }, /client_uri/);
		await refuses("scope", { scope: ["read"] }, /scope/);
		const { resolve } = resolver({}, [
			() => json(document({ client_name: "  Padded  ", client_uri: undefined })),
		]);
		const client = await resolve();
		expect(client?.clientName).toBe("Padded");
		expect(client?.clientUri).toBeUndefined();
	});
});

describe("createClientIdMetadataDocumentResolver — caching (#529)", () => {
	it("serves a valid document from cache for max-age, bounded by cacheMaxAgeMs, and revalidates by ETag", async () => {
		let t = 1_000_000;
		const { resolve, calls } = resolver({ now: () => t, cacheMaxAgeMs: 60_000 }, [
			() => json(document(), { "cache-control": "max-age=3600", etag: '"v1"' }),
			() => new Response(null, { status: 304, headers: { "cache-control": "max-age=30" } }),
			() => json(document({ client_name: "Renamed" }), { etag: '"v2"' }),
		]);
		expect((await resolve())?.clientName).toBe("Acme Chat");
		expect((await resolve())?.clientName).toBe("Acme Chat");
		expect(calls).toHaveLength(1); // cached

		t += 60_001; // past the operator's bound, though max-age had an hour left
		expect((await resolve())?.clientName).toBe("Acme Chat");
		expect(calls).toHaveLength(2);
		const revalidation = (calls[1]?.init?.headers ?? {}) as Record<string, string>;
		expect(revalidation["if-none-match"]).toBe('"v1"');

		t += 30_001; // the 304 granted 30 s
		expect((await resolve())?.clientName).toBe("Renamed");
		expect(calls).toHaveLength(3);
	});

	it("never caches an error or an invalid document, and respects no-store", async () => {
		const failing = resolver({}, [() => json({}, {}, 500), () => json(document())]);
		expect(await failing.resolve()).toBeNull();
		expect(await failing.resolve()).not.toBeNull();
		expect(failing.calls).toHaveLength(2);

		const invalid = resolver({}, [
			() => json(document({ redirect_uris: [] })),
			() => json(document()),
		]);
		expect(await invalid.resolve()).toBeNull();
		expect(await invalid.resolve()).not.toBeNull();

		const noStore = resolver({}, [
			() => json(document(), { "cache-control": "no-store" }),
			() => json(document()),
		]);
		await noStore.resolve();
		await noStore.resolve();
		expect(noStore.calls).toHaveLength(2);
	});

	it("shares one fetch between concurrent lookups of the same URL", async () => {
		const { resolve, calls } = resolver({}, [() => json(document())]);
		const [a, b] = await Promise.all([resolve(), resolve()]);
		expect(a).toEqual(b);
		expect(calls).toHaveLength(1);
	});
});

describe("withClientIdMetadataDocuments (#529)", () => {
	const inner: ClientRepository = {
		findById: async (id) =>
			id === "registered" || id === CLIENT_URL
				? ({
						clientId: id,
						tokenEndpointAuthMethod: "none",
						allowedRedirectUris: [],
						allowedScopes: [],
						firstParty: true,
					} as never)
				: null,
		authenticate: async () => null,
	};

	it("answers pre-registered clients first — a registered URL wins over its document, unfetched", async () => {
		const { fetch, calls } = fakeFetch([() => json(document())]);
		const repo = withClientIdMetadataDocuments(inner, {
			allowedScopes: [],
			allowedAudiences: [],
			fetch,
			lookup: publicLookup,
		});
		expect((await repo.findById("registered"))?.firstParty).toBe(true);
		expect((await repo.findById(CLIENT_URL))?.firstParty).toBe(true);
		expect(calls).toHaveLength(0);
		expect(await repo.findById("nobody")).toBeNull();
	});

	it("falls through to the document for an unregistered URL, and never authenticates one", async () => {
		const { fetch } = fakeFetch([
			() => json(document({ client_id: "https://other.example/meta" })),
		]);
		const repo = withClientIdMetadataDocuments(inner, {
			allowedScopes: ["read"],
			allowedAudiences: [],
			fetch,
			lookup: publicLookup,
		});
		expect((await repo.findById("https://other.example/meta"))?.firstParty).toBe(false);
		expect(await repo.authenticate("https://other.example/meta", "secret")).toBeNull();
	});
});

describe("the document cache is bounded (#529 review)", () => {
	it("evicts the oldest entry rather than growing without limit", async () => {
		// An unauthenticated caller chooses the keys: every URL that serves a
		// valid document is a `client_id`, so the map cannot be unbounded.
		const urls = [
			"https://a.example/meta.json",
			"https://b.example/meta.json",
			"https://c.example/meta.json",
		];
		const { fetch, calls } = fakeFetch(
			Array.from({ length: 8 }, () => () => json(document({ client_id: "PLACEHOLDER" }))),
		);
		// Each response must name the URL it was fetched from.
		const r = createClientIdMetadataDocumentResolver({
			allowedScopes: ["read", "write"],
			allowedAudiences: ["https://mcp.example"],
			maxCacheEntries: 2,
			lookup: publicLookup,
			fetch: (async (input: string | URL | Request, init?: RequestInit) => {
				const url = typeof input === "string" ? input : input.toString();
				void (await fetch(url, init));
				return json(document({ client_id: url }));
			}) as unknown as typeof globalThis.fetch,
		});

		for (const url of urls) expect(await r.resolve(url)).not.toBeNull();
		expect(calls).toHaveLength(3);
		// The two most recent are remembered; the first was evicted and is
		// fetched again.
		expect(await r.resolve(urls[1] as string)).not.toBeNull();
		expect(await r.resolve(urls[2] as string)).not.toBeNull();
		expect(calls).toHaveLength(3);
		expect(await r.resolve(urls[0] as string)).not.toBeNull();
		expect(calls).toHaveLength(4);
	});
});
