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
			// A trailing dot is the DNS root, and it survives canonicalisation:
			// `new URL(...).href` returns it unchanged and TLS accepts the
			// certificate issued for the undotted name. `deniedHosts` matches on
			// neither spelling, so the operator's deny list read as a pass.
			"https://client.example./meta",
			"https://client.example.:8443/meta",
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
		// Each of these is the client's own registration being wrong or absent,
		// so each is logged as a rejection — the log an operator reads to tell
		// "this client is misconfigured" from "their server is having a bad
		// day", which is the `cimd_document_fetch_failed` case below.
		for (const [name, response] of [
			[
				"redirect",
				() => new Response(null, { status: 302, headers: { location: "https://elsewhere" } }),
			],
			["404", () => json({}, {}, 404)],
			["403", () => json({}, {}, 403)],
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

	it("reports the client server's own failure as a fetch failure, not a rejection", async () => {
		// A 5xx or a 429 is their availability, not their registration. The
		// distinction decides whether a warm entry survives (#529 audit) — and
		// it is the one an operator needs from the log.
		for (const [name, response] of [
			["500", () => json({}, {}, 500)],
			["503", () => json({}, {}, 503)],
			["429", () => json({}, {}, 429)],
		] as const) {
			const { resolve, warn } = resolver({}, [response]);
			expect(await resolve(), name).toBeNull();
			expect(warn, name).toHaveBeenCalledWith(expect.anything(), "cimd_document_fetch_failed");
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

	it("never caches an error or an invalid document as a client, and respects no-store", async () => {
		// A refusal is remembered as a refusal for a bounded window (#529
		// audit) — never as a client, and never for long: the retry after the
		// window is a real fetch, so a client that fixes its document is not
		// locked out. What must not happen is re-fetching the refusal on every
		// request, which is what made an unauthenticated caller's outbound cost
		// unbounded.
		const clock = { now: 1_000_000 };
		const failing = resolver({ now: () => clock.now }, [
			() => json({}, {}, 500),
			() => json(document()),
		]);
		expect(await failing.resolve()).toBeNull();
		expect(await failing.resolve()).toBeNull();
		expect(failing.calls).toHaveLength(1);
		clock.now += 120_000;
		expect(await failing.resolve()).not.toBeNull();
		expect(failing.calls).toHaveLength(2);

		const invalidClock = { now: 1_000_000 };
		const invalid = resolver({ now: () => invalidClock.now }, [
			() => json(document({ redirect_uris: [] })),
			() => json(document()),
		]);
		expect(await invalid.resolve()).toBeNull();
		expect(await invalid.resolve()).toBeNull();
		invalidClock.now += 120_000;
		expect(await invalid.resolve()).not.toBeNull();

		// A success the client asked not to be stored is fetched again, and the
		// success cleared any refusal that preceded it.
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

describe("the host policy holds whichever way the name is spelled (#529 audit)", () => {
	it("does not let a trailing dot walk past deniedHosts", async () => {
		// `allowedHosts` fails closed on the dotted form — it matches nothing —
		// but `deniedHosts` failed open: neither "client.example" nor
		// ".client.example" matches "client.example.", so a denied host was
		// reachable by adding one character the resolver, DNS and TLS all
		// ignore.
		const dotted = CLIENT_URL.replace("client.example", "client.example.");
		const denied = resolver({ deniedHosts: ["client.example"] });
		expect(await denied.resolve(dotted)).toBeNull();
		// Refused before the socket opens, which is what "denied" has to mean:
		// null alone was reached anyway, because the document's own `client_id`
		// is the undotted spelling and could never equal what was asked for.
		expect(denied.calls).toHaveLength(0);
	});

	it("refuses the dotted spelling even where the undotted one is allowed", async () => {
		const dotted = CLIENT_URL.replace("client.example", "client.example.");
		const allowed = resolver({ allowedHosts: ["client.example"] });
		expect(await allowed.resolve(dotted)).toBeNull();
		expect(allowed.calls).toHaveLength(0);
	});
});

describe("the cache tells the truth about an outage (#529 audit)", () => {
	it("serves a cached registration through a failed revalidation rather than breaking the client", async () => {
		// The catch deleted the entry and answered `null` for every error — a
		// DNS blip, a 5xx, a timeout — which `/authorize` turns into
		// `invalid_client`. That is the distinction this codebase draws
		// everywhere else (#408): telling a caller their credential is bad when
		// the truth is that a backend is unreachable. Defensible on a cold
		// lookup; on a warm cache it is a working client broken by someone
		// else's outage.
		const clock = { now: 1_000_000 };
		const { fetch, calls } = fakeFetch([
			() => json(document(), { "cache-control": "max-age=1" }),
			() => {
				throw new Error("connect ETIMEDOUT");
			},
		]);
		const r = createClientIdMetadataDocumentResolver({
			allowedScopes: ["read", "write"],
			allowedAudiences: ["https://mcp.example"],
			fetch,
			lookup: publicLookup,
			now: () => clock.now,
		});

		expect(await r.resolve(CLIENT_URL)).not.toBeNull();
		clock.now += 2_000; // the entry has expired, so this revalidates
		expect(await r.resolve(CLIENT_URL)).not.toBeNull();
		expect(calls).toHaveLength(2);
	});

	it("rides out the client server's own 5xx on a warm cache", async () => {
		// A 503 from the client's server is not a verdict on the client. It
		// reached this code as `DocumentRejected` — every non-200 did — so the
		// warm registration was deleted and the client refused, which is the
		// case the stale window exists for.
		const clock = { now: 1_000_000 };
		const { fetch } = fakeFetch([
			() => json(document(), { "cache-control": "max-age=1" }),
			() => json({ error: "down" }, {}, 503),
			() => json({ error: "slow down" }, {}, 429),
		]);
		const r = createClientIdMetadataDocumentResolver({
			allowedScopes: ["read", "write"],
			allowedAudiences: ["https://mcp.example"],
			fetch,
			lookup: publicLookup,
			now: () => clock.now,
		});

		expect(await r.resolve(CLIENT_URL)).not.toBeNull();
		clock.now += 2_000;
		expect(await r.resolve(CLIENT_URL)).not.toBeNull();
		clock.now += 2_000;
		expect(await r.resolve(CLIENT_URL)).not.toBeNull();
	});

	it("treats a 404 as the client's own problem, not an outage", async () => {
		// The other side of the same line: the registration is not there, so
		// the warm entry goes and the refusal is remembered.
		const clock = { now: 1_000_000 };
		const { fetch } = fakeFetch([
			() => json(document(), { "cache-control": "max-age=1" }),
			() => json({ error: "gone" }, {}, 404),
		]);
		const r = createClientIdMetadataDocumentResolver({
			allowedScopes: ["read", "write"],
			allowedAudiences: ["https://mcp.example"],
			fetch,
			lookup: publicLookup,
			now: () => clock.now,
		});

		expect(await r.resolve(CLIENT_URL)).not.toBeNull();
		clock.now += 2_000;
		expect(await r.resolve(CLIENT_URL)).toBeNull();
	});

	it("still refuses a document that was rejected, cache or no cache", async () => {
		// A document the server will not honour is not an outage: the client
		// stops being a client the moment its registration stops being valid.
		const clock = { now: 1_000_000 };
		const { fetch } = fakeFetch([
			() => json(document(), { "cache-control": "max-age=1" }),
			() => json({ ...document(), redirect_uris: [] }),
		]);
		const r = createClientIdMetadataDocumentResolver({
			allowedScopes: ["read"],
			allowedAudiences: [],
			fetch,
			lookup: publicLookup,
			now: () => clock.now,
		});

		expect(await r.resolve(CLIENT_URL)).not.toBeNull();
		clock.now += 2_000;
		expect(await r.resolve(CLIENT_URL)).toBeNull();
		// And it is gone: the next lookup is not served the stale one either.
		expect(await r.resolve(CLIENT_URL)).toBeNull();
	});

	it("does not re-fetch a refusal on every request", async () => {
		// Failures were never cached, so N distinct URL-shaped client_ids cost
		// N DNS resolutions and N TLS handshakes, every time — an attacker's
		// tarpit pins a socket for the whole timeout, and a third party's 404
		// is hammered from this server's address.
		const clock = { now: 1_000_000 };
		const { fetch, calls } = fakeFetch([
			() => json({ error: "nope" }, {}, 404),
			() => json({ error: "nope" }, {}, 404),
		]);
		const r = createClientIdMetadataDocumentResolver({
			allowedScopes: ["read"],
			allowedAudiences: [],
			fetch,
			lookup: publicLookup,
			now: () => clock.now,
		});

		expect(await r.resolve(CLIENT_URL)).toBeNull();
		expect(await r.resolve(CLIENT_URL)).toBeNull();
		expect(calls).toHaveLength(1);

		// Bounded, not permanent: a client that fixes its document is not
		// locked out for the life of the process.
		clock.now += 120_000;
		expect(await r.resolve(CLIENT_URL)).toBeNull();
		expect(calls).toHaveLength(2);
	});

	it("bounds how many documents it fetches at once", async () => {
		// Concurrency is per URL only, so distinct ids fan out without limit:
		// N slow hosts hold N sockets for the whole timeout each.
		const started: string[] = [];
		let release: () => void = () => {};
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const slowFetch = (async (input: string | URL | Request) => {
			started.push(String(input));
			await gate;
			return json(document({ client_id: String(input) }));
		}) as typeof fetch;
		const r = createClientIdMetadataDocumentResolver({
			allowedScopes: ["read"],
			allowedAudiences: [],
			maxConcurrentFetches: 2,
			fetch: slowFetch,
			lookup: publicLookup,
		});

		const ids = Array.from({ length: 6 }, (_, i) => `https://client.example/meta-${i}`);
		const all = Promise.all(ids.map((id) => r.resolve(id)));
		await vi.waitFor(() => expect(started.length).toBe(2));
		// The other four are waiting for a slot, not for a socket.
		expect(started).toHaveLength(2);
		release();
		await all;
		expect(started).toHaveLength(6);
	});
});

describe("the refusal memo and the stale window are bounded (#529 audit)", () => {
	it("bounds the refusal memo the same way it bounds the documents", async () => {
		// The keys here are the caller's too: an id that refuses is an id the
		// caller invented, so remembering every one of them would hand the
		// memory back to whoever was being throttled.
		const clock = { now: 1_000_000 };
		const r = createClientIdMetadataDocumentResolver({
			allowedScopes: ["read"],
			allowedAudiences: [],
			maxCacheEntries: 2,
			fetch: (async () => json({ error: "nope" }, {}, 404)) as typeof fetch,
			lookup: publicLookup,
			now: () => clock.now,
		});

		for (let i = 0; i < 5; i += 1) {
			expect(await r.resolve(`https://client.example/meta-${i}`)).toBeNull();
		}
		// The earliest refusals were evicted, so their ids are fetched again
		// rather than answered from a memo that grew without limit.
		const fetched: string[] = [];
		const counting = createClientIdMetadataDocumentResolver({
			allowedScopes: ["read"],
			allowedAudiences: [],
			maxCacheEntries: 2,
			fetch: (async (input: string | URL | Request) => {
				fetched.push(String(input));
				return json({ error: "nope" }, {}, 404);
			}) as typeof fetch,
			lookup: publicLookup,
			now: () => clock.now,
		});
		for (let i = 0; i < 3; i += 1) await counting.resolve(`https://client.example/m-${i}`);
		await counting.resolve("https://client.example/m-0");
		expect(fetched).toHaveLength(4);
	});

	it("stops serving a stale registration once its window has lapsed", async () => {
		// The window is anchored to the last successful fetch, so it does not
		// renew itself for the length of an outage: eventually the client is
		// refused rather than served a registration nobody can revalidate.
		const clock = { now: 1_000_000 };
		let fail = false;
		const r = createClientIdMetadataDocumentResolver({
			allowedScopes: ["read", "write"],
			allowedAudiences: [],
			cacheMaxAgeMs: 1_000,
			staleIfErrorMs: 5_000,
			negativeCacheMs: 0,
			fetch: (async () => {
				if (fail) throw new Error("connect ETIMEDOUT");
				return json(document(), { "cache-control": "max-age=1" });
			}) as typeof fetch,
			lookup: publicLookup,
			now: () => clock.now,
		});

		expect(await r.resolve(CLIENT_URL)).not.toBeNull();
		fail = true;
		clock.now += 2_000; // expired; revalidation fails, so the stale one is served
		expect(await r.resolve(CLIENT_URL)).not.toBeNull();
		clock.now += 10_000; // past the deadline from the last success
		expect(await r.resolve(CLIENT_URL)).toBeNull();
	});
});
