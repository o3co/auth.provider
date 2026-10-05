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
 * Client ID Metadata Documents: a client whose `client_id` is the
 * `https` URL of its own registration. Almost every case is a refusal, and
 * the ones that are not pin what the fetched document turns into. No network:
 * `fetch` is the resolver's seam, a canned `fetch` or core's outbound fetch
 * over a resolver and a transport the test supplies; the cases that pass
 * neither are refused before any name is resolved.
 */

import type { ClientRepository, Logger } from "@o3co/auth-provider-core";
import {
	createOutboundFetchForTesting,
	type OutboundAnswer,
	type OutboundExchange,
	withOutbound,
} from "@o3co/auth-provider-core/testing";
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

const publicLookup = async (): Promise<readonly string[]> => ["93.184.216.34"];

const resolver = (
	over: Partial<ClientIdMetadataDocumentOptions> = {},
	responses: Array<() => Response> = [() => json(document())],
) => {
	const { fetch, calls } = fakeFetch(responses);
	const warn = vi.fn();
	const logger = { warn, info: vi.fn(), error: vi.fn(), debug: vi.fn() } as unknown as Logger;
	const r = createClientIdMetadataDocumentResolver({
		config: {},
		allowedScopes: ["read", "write"],
		allowedAudiences: ["https://mcp.example"],
		fetch,
		logger,
		...over,
	});
	return { resolve: (id = CLIENT_URL) => r.resolve(id), calls, warn };
};

/** A peer's answer as core's transport hands it on: `body` arrives in one chunk. */
const answer = (
	status: number,
	headers: Record<string, string> = {},
	body = "",
): OutboundAnswer => ({
	status,
	statusText: "",
	headers: Object.entries(headers),
	body: (async function* () {
		if (body !== "") yield new TextEncoder().encode(body);
	})(),
	close: () => undefined,
});

/** A peer's answer whose body never arrives. */
const stalled = (status: number, headers: Record<string, string> = {}): OutboundAnswer => ({
	status,
	statusText: "",
	headers: Object.entries(headers),
	body: { [Symbol.asyncIterator]: () => ({ next: () => new Promise<never>(() => undefined) }) },
	close: () => undefined,
});

const jsonAnswer = (body: unknown, headers: Record<string, string> = {}, status = 200) =>
	answer(status, { "content-type": "application/json", ...headers }, JSON.stringify(body));

/**
 * Core's outbound fetch for a URL a request names, as the resolver builds it,
 * over a resolver and a transport the test supplies (both below the policy):
 * what it resolved, and every exchange with the addresses it may connect to.
 */
const outbound = (
	answers: Array<() => OutboundAnswer>,
	opts: {
		readonly lookup?: (hostname: string) => Promise<readonly string[]>;
		readonly config?: unknown;
		readonly maxResponseBytes?: number;
	} = {},
) => {
	const lookups: string[] = [];
	const exchanges: OutboundExchange[] = [];
	const lookup = opts.lookup ?? publicLookup;
	const fetch = createOutboundFetchForTesting({
		config: opts.config ?? {},
		source: "request",
		maxResponseBytes: opts.maxResponseBytes ?? DEFAULT_CIMD_MAX_BYTES,
		lookup: async (hostname) => {
			lookups.push(hostname);
			return lookup(hostname);
		},
		transport: async (exchange) => {
			exchanges.push(exchange);
			const next = answers.shift();
			if (next === undefined) throw new Error("transport: no answer queued");
			return next();
		},
	});
	return { fetch, lookups, exchanges };
};

/**
 * What the warn line logged as `event` says failed: its `reason`, then the
 * `reason` code of the error that caused it (a refusal by core's outbound
 * policy travels as the cause).
 */
const reasonOf = (warn: ReturnType<typeof vi.fn>, event: string): string => {
	const line = warn.mock.calls.find(([, name]) => name === event);
	expect(line, event).toBeDefined();
	const fields = line?.[0] as
		| { reason?: unknown; err?: { cause?: { reason?: unknown } } }
		| undefined;
	return `${String(fields?.reason)} / ${String(fields?.err?.cause?.reason)}`;
};

describe("isClientIdMetadataDocumentUrl (draft §3.1)", () => {
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

describe("createClientIdMetadataDocumentResolver — what a document becomes", () => {
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
		expect(calls[0]?.init).toMatchObject({ method: "GET" });
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

	it("reads the document's scope by RFC 6749 §3.3's grammar, tolerantly, and never widens on one it cannot read", async () => {
		// A third party's document: split on any whitespace and keep the
		// scope-tokens, as an upstream's answer is read (parseScopeTokens). A
		// scope named, but naming no scope-token, is not an absent one: it is
		// not the operator's whole ceiling.
		const tab = resolver({}, [() => json(document({ scope: "read\twrite\tadmin" }))]);
		expect((await tab.resolve())?.allowedScopes).toEqual(["read", "write"]);
		const unreadable = resolver({}, [() => json(document({ scope: '\t"read"' }))]);
		expect((await unreadable.resolve())?.allowedScopes).toEqual([]);
	});

	it("is not a client at all when the id is not a document URL, without fetching", async () => {
		const { resolve, calls } = resolver();
		expect(await resolve("mobile-app")).toBeNull();
		expect(await resolve("http://client.example/meta")).toBeNull();
		expect(calls).toHaveLength(0);
	});
});

describe("createClientIdMetadataDocumentResolver — the destination and the host policy", () => {
	it("refuses a host that resolves to a special-use address, before any connection", async () => {
		for (const address of [
			"127.0.0.1",
			"10.0.0.5",
			"169.254.169.254",
			"::1",
			"::ffff:192.168.0.1",
		]) {
			const { fetch, exchanges } = outbound([() => jsonAnswer(document())], {
				lookup: async () => ["93.184.216.34", address],
			});
			const { resolve, warn } = resolver({ fetch });
			expect(await resolve(), address).toBeNull();
			expect(exchanges, address).toHaveLength(0);
			expect(reasonOf(warn, "cimd_document_rejected"), address).toContain("special_use_address");
		}
	});

	it("refuses a name that does not resolve, or whose lookup fails, without connecting", async () => {
		// Resolution failing is the network, not the document: a fetch failure.
		const empty = outbound([() => jsonAnswer(document())], { lookup: async () => [] });
		const emptyResolver = resolver({ fetch: empty.fetch });
		expect(await emptyResolver.resolve()).toBeNull();
		expect(empty.exchanges).toHaveLength(0);
		expect(emptyResolver.warn).toHaveBeenCalledWith(
			expect.anything(),
			"cimd_document_fetch_failed",
		);
		const failing = outbound([() => jsonAnswer(document())], {
			lookup: async () => {
				throw new Error("ENOTFOUND");
			},
		});
		const failingResolver = resolver({ fetch: failing.fetch });
		expect(await failingResolver.resolve()).toBeNull();
		expect(failing.exchanges).toHaveLength(0);
		expect(failingResolver.warn).toHaveBeenCalledWith(
			expect.anything(),
			"cimd_document_fetch_failed",
		);
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

describe("createClientIdMetadataDocumentResolver — what a refusal logs of the client's text", () => {
	// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be logged.
	const CONTROL = /[\u0000-\u001f\u007f]/;
	/** The one warn line, as an assertion needs it: a failure prints this, not the line. */
	const onlyLine = (warn: ReturnType<typeof vi.fn>, event: string) => {
		expect(warn).toHaveBeenCalledTimes(1);
		const [line, name] = warn.mock.calls[0] as [Record<string, unknown>, string];
		expect(name).toBe(event);
		return line;
	};

	/**
	 * A 200 answer whose Content-Type is `contentType`. A real `Response`
	 * refuses a line break in a header value; a `fetch` a deployment wires is
	 * under no such obligation, so that case is a Response-shaped answer.
	 */
	const answeringContentType = (contentType: string) => (): Response =>
		({
			status: 200,
			headers: { get: (name: string) => (name === "content-type" ? contentType : null) },
			body: null,
		}) as unknown as Response;

	it.each([
		["control characters and 10 000 characters", `text/html\u001b[31m\u0007${"x".repeat(10_000)}`],
		["a line break", `text/html\r\nFORGED cimd_document_rejected${"x".repeat(10_000)}`],
	])("quotes a Content-Type carrying %s sanitised and capped", async (_label, contentType) => {
		const { resolve, warn } = resolver({}, [answeringContentType(contentType)]);

		expect(await resolve()).toBeNull();
		const line = onlyLine(warn, "cimd_document_rejected");
		const reason = String(line.reason);
		const detail = String((line.err as { detail?: unknown }).detail);
		expect({
			reasonControl: CONTROL.test(reason),
			detailControl: CONTROL.test(detail),
			reasonClosed: reason.endsWith("...)"),
		}).toEqual({ reasonControl: false, detailControl: false, reasonClosed: true });
		expect(reason.startsWith("document is not JSON (Content-Type: text/html?")).toBe(true);
	});

	it("quotes a token_endpoint_auth_method the document names, sanitised as auditErrorText does", async () => {
		const { resolve, warn } = resolver({}, [
			() => json(document({ token_endpoint_auth_method: 'a"b\u2028c\u202e\u007f' })),
		]);

		expect(await resolve()).toBeNull();
		expect(onlyLine(warn, "cimd_document_rejected").reason).toBe(
			"token_endpoint_auth_method 'a?b?c??' is not allowed for a Client ID Metadata Document",
		);
	});

	it("quotes a redirect_uris entry sanitised, and says why it is refused", async () => {
		const { resolve, warn } = resolver({}, [
			() => json(document({ redirect_uris: ["http://evil.example/cb\u2028\u202e"] })),
		]);

		expect(await resolve()).toBeNull();
		expect(onlyLine(warn, "cimd_document_rejected").reason).toBe(
			"redirect_uris entry 'http://evil.example/cb??' is not acceptable: http:// is accepted for loopback hosts only (localhost, 127.0.0.0/8, [::1]); got host \"evil.example\"",
		);
	});

	it("still quotes an ordinary Content-Type exactly", async () => {
		const { resolve, warn } = resolver({}, [
			() => new Response("<html/>", { status: 200, headers: { "content-type": "text/html" } }),
		]);

		expect(await resolve()).toBeNull();
		expect(onlyLine(warn, "cimd_document_rejected").reason).toBe(
			"document is not JSON (Content-Type: text/html)",
		);
	});

	// A real route never gets here with one: `/authorize` and client
	// authentication refuse a client id over 256 characters
	// (`MAX_CLIENT_ID_LENGTH`) before the resolver is asked. These drive the
	// resolver directly, the one place a longer id could still reach a line.
	const LONG_ID = `https://client.example/${"p".repeat(10_000)}`;

	it("logs a 10 000-character client id capped when its document is refused", async () => {
		const { resolve, warn } = resolver({}, [
			() => new Response("<html/>", { status: 200, headers: { "content-type": "text/html" } }),
		]);

		expect(await resolve(LONG_ID)).toBeNull();
		const clientId = String(onlyLine(warn, "cimd_document_rejected").clientId);
		expect({ within200: clientId.length <= 200, head: clientId.slice(0, 23) }).toEqual({
			within200: true,
			head: "https://client.example/",
		});
	});

	it("logs a 10 000-character client id capped when its host is not allowed", async () => {
		const { resolve, warn } = resolver({ allowedHosts: ["other.example"] });

		expect(await resolve(LONG_ID)).toBeNull();
		const clientId = String(onlyLine(warn, "cimd_host_not_allowed").clientId);
		expect(clientId.length <= 200).toBe(true);
	});
});

describe("createClientIdMetadataDocumentResolver — the fetch", () => {
	it("refuses a redirect, and follows none", async () => {
		const { fetch, exchanges } = outbound([
			() => answer(302, { location: "https://elsewhere.example/meta" }),
			() => jsonAnswer(document()),
		]);
		const { resolve, warn } = resolver({ fetch });
		expect(await resolve()).toBeNull();
		expect(exchanges).toHaveLength(1);
		expect(reasonOf(warn, "cimd_document_rejected")).toContain("redirect_refused");
	});

	it("refuses a non-200 and a non-JSON body", async () => {
		// Each of these is the client's own registration being wrong or absent,
		// so each is logged as a rejection — the log an operator reads to tell
		// "this client is misconfigured" from "their server is having a bad
		// day", which is the `cimd_document_fetch_failed` case below.
		for (const [name, response] of [
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
		// distinction decides whether a warm entry survives — and
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
		const declared = outbound([
			() =>
				answer(
					200,
					{ "content-type": "application/json", "content-length": String(big.length) },
					big,
				),
		]);
		const declaredResolver = resolver({ fetch: declared.fetch });
		expect(await declaredResolver.resolve()).toBeNull();
		expect(reasonOf(declaredResolver.warn, "cimd_document_rejected")).toContain(
			"response_too_large",
		);
		// No Content-Length: the stream is what stops it.
		const streamed = outbound([() => answer(200, { "content-type": "application/json" }, big)]);
		const streamedResolver = resolver({ fetch: streamed.fetch });
		expect(await streamedResolver.resolve()).toBeNull();
		expect(reasonOf(streamedResolver.warn, "cimd_document_rejected")).toContain(
			"response_too_large",
		);
		// A small cap can be raised by the operator.
		const roomy = outbound([() => jsonAnswer(JSON.parse(big))], {
			maxResponseBytes: big.length + 1,
		});
		expect(await resolver({ fetch: roomy.fetch }).resolve()).not.toBeNull();
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

	it("logs a thrown value that is not an Error by its kind, never its content", async () => {
		// A projection with no message — a thrown non-Error, a SyntaxError —
		// gives its name as the reason.
		const { resolve, warn } = resolver({}, [
			() => {
				throw "socket hang up: thrown-text-must-never-reach-a-log";
			},
		]);
		expect(await resolve()).toBeNull();
		expect(warn).toHaveBeenCalledWith(
			{
				clientId: CLIENT_URL,
				reason: "NonError",
				err: { name: "NonError", thrown: "string" },
			},
			"cimd_document_fetch_failed",
		);
		expect(JSON.stringify(warn.mock.calls)).not.toContain("thrown-text-must-never-reach-a-log");
	});

	it("logs a fetch failure's cause code beside its reason, through the projection", async () => {
		// undici's "fetch failed" says nothing on its own; the code on its
		// cause (ECONNREFUSED, ENOTFOUND, a TLS failure) is what an operator
		// acts on.
		const { resolve, warn } = resolver({}, [
			() => {
				throw new TypeError("fetch failed", {
					cause: Object.assign(new Error("connect ECONNREFUSED 93.184.216.34:443"), {
						code: "ECONNREFUSED",
					}),
				});
			},
		]);
		expect(await resolve()).toBeNull();
		expect(warn).toHaveBeenCalledWith(
			expect.objectContaining({
				reason: "fetch failed",
				err: expect.objectContaining({
					name: "TypeError",
					cause: expect.objectContaining({ code: "ECONNREFUSED" }),
				}),
			}),
			"cimd_document_fetch_failed",
		);
	});
});

describe("createClientIdMetadataDocumentResolver — the document", () => {
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

	it("refuses a redirect_uris entry whose query core's redirect-URI rule refuses", async () => {
		await refuses(
			"a response parameter",
			{ redirect_uris: ["https://client.example/cb?iss=x"] },
			/redirect_uris entry .* must not carry "iss" in its query/,
		);
		await refuses(
			"a bracketed name",
			{ redirect_uris: ["https://client.example/cb?filter[x]=1"] },
			/redirect_uris entry .* query parameter names may use only/,
		);
	});

	it("refuses a shared-secret method, a client_secret, and private_key_jwt", async () => {
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
		// The consent page shows this, and a document client is by
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

describe("createClientIdMetadataDocumentResolver — caching", () => {
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
		// A refusal is remembered as a refusal for a bounded window — never as
		// a client, and never for long: the retry after the window is a real
		// fetch, so a client that fixes its document is not locked out. What
		// must not happen is re-fetching the refusal on every request, which
		// would make an unauthenticated caller's outbound cost unbounded.
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

describe("withClientIdMetadataDocuments", () => {
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
			config: {},
			allowedScopes: [],
			allowedAudiences: [],
			fetch,
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
			config: {},
			allowedScopes: ["read"],
			allowedAudiences: [],
			fetch,
		});
		expect((await repo.findById("https://other.example/meta"))?.firstParty).toBe(false);
		expect(await repo.authenticate("https://other.example/meta", "secret")).toBeNull();
	});
});

describe("the document cache is bounded", () => {
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
			config: {},
			allowedScopes: ["read", "write"],
			allowedAudiences: ["https://mcp.example"],
			maxCacheEntries: 2,
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

describe("the host policy holds whichever way the name is spelled", () => {
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

describe("the cache tells the truth about an outage", () => {
	it("serves a cached registration through a failed revalidation rather than breaking the client", async () => {
		// Deleting the entry and answering `null` for every error — a DNS
		// blip, a 5xx, a timeout — would have `/authorize` answer
		// `invalid_client`: telling a caller their credential is bad when the
		// truth is that a backend is unreachable, which this codebase refuses
		// everywhere else. Defensible on a cold lookup; on a warm cache it is a
		// working client broken by someone else's outage.
		const clock = { now: 1_000_000 };
		const { fetch, calls } = fakeFetch([
			() => json(document(), { "cache-control": "max-age=1" }),
			() => {
				throw new Error("connect ETIMEDOUT");
			},
		]);
		const r = createClientIdMetadataDocumentResolver({
			config: {},
			allowedScopes: ["read", "write"],
			allowedAudiences: ["https://mcp.example"],
			fetch,
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
			config: {},
			allowedScopes: ["read", "write"],
			allowedAudiences: ["https://mcp.example"],
			fetch,
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
			config: {},
			allowedScopes: ["read", "write"],
			allowedAudiences: ["https://mcp.example"],
			fetch,
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
			config: {},
			allowedScopes: ["read"],
			allowedAudiences: [],
			fetch,
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
			config: {},
			allowedScopes: ["read"],
			allowedAudiences: [],
			fetch,
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
			config: {},
			allowedScopes: ["read"],
			allowedAudiences: [],
			maxConcurrentFetches: 2,
			fetch: slowFetch,
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

describe("the refusal memo and the stale window are bounded", () => {
	it("bounds the refusal memo the same way it bounds the documents", async () => {
		// The keys here are the caller's too: an id that refuses is an id the
		// caller invented, so remembering every one of them would hand the
		// memory back to whoever was being throttled.
		const clock = { now: 1_000_000 };
		const r = createClientIdMetadataDocumentResolver({
			config: {},
			allowedScopes: ["read"],
			allowedAudiences: [],
			maxCacheEntries: 2,
			fetch: (async () => json({ error: "nope" }, {}, 404)) as typeof fetch,
			now: () => clock.now,
		});

		for (let i = 0; i < 5; i += 1) {
			expect(await r.resolve(`https://client.example/meta-${i}`)).toBeNull();
		}
		// The earliest refusals were evicted, so their ids are fetched again
		// rather than answered from a memo that grew without limit.
		const fetched: string[] = [];
		const counting = createClientIdMetadataDocumentResolver({
			config: {},
			allowedScopes: ["read"],
			allowedAudiences: [],
			maxCacheEntries: 2,
			fetch: (async (input: string | URL | Request) => {
				fetched.push(String(input));
				return json({ error: "nope" }, {}, 404);
			}) as typeof fetch,
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
			config: {},
			allowedScopes: ["read", "write"],
			allowedAudiences: [],
			cacheMaxAgeMs: 1_000,
			staleIfErrorMs: 5_000,
			negativeCacheMs: 0,
			fetch: (async () => {
				if (fail) throw new Error("connect ETIMEDOUT");
				return json(document(), { "cache-control": "max-age=1" });
			}) as typeof fetch,
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

describe("the document is fetched through core's outbound policy", () => {
	it("resolves the name once and connects only to the address it checked", async () => {
		// A resolver that answers differently the second time: the one answer
		// that was checked is the one connected to.
		let answered = 0;
		const { fetch, lookups, exchanges } = outbound([() => jsonAnswer(document())], {
			lookup: async () => (answered++ === 0 ? ["93.184.216.34"] : ["10.0.0.5"]),
		});
		const { resolve } = resolver({ fetch });

		expect(await resolve()).not.toBeNull();
		expect(lookups).toEqual(["client.example"]);
		expect(exchanges.map((exchange) => exchange.addresses)).toEqual([["93.184.216.34"]]);
	});

	it("refuses a host core.outbound.deniedHosts lists, before resolving it", async () => {
		const { resolve, warn } = resolver({
			fetch: undefined,
			config: withOutbound({}, { deniedHosts: ["client.example"] }),
		});

		expect(await resolve()).toBeNull();
		expect(reasonOf(warn, "cimd_document_rejected")).toContain("host_not_allowed");
	});

	it("refuses a document on a port fetch never connects to, before resolving it", async () => {
		const id = "https://client.example:636/meta";
		const { resolve, warn } = resolver({ fetch: undefined });

		expect(await resolve(id)).toBeNull();
		expect(reasonOf(warn, "cimd_document_rejected")).toContain("port_not_allowed");
	});

	it("never admits a special-use address for a document, even for a host core.outbound.internalHosts lists", async () => {
		const config = withOutbound({}, { internalHosts: ["client.example"] });
		const { fetch, exchanges } = outbound([() => jsonAnswer(document())], {
			config,
			lookup: async () => ["10.0.0.5"],
		});
		const { resolve, warn } = resolver({ fetch, config });

		expect(await resolve()).toBeNull();
		expect(exchanges).toHaveLength(0);
		expect(reasonOf(warn, "cimd_document_rejected")).toContain("special_use_address");
	});

	it("rejects a document sent in an encoding other than identity", async () => {
		const { fetch } = outbound([() => jsonAnswer(document(), { "content-encoding": "gzip" })]);
		const { resolve, warn } = resolver({ fetch });

		expect(await resolve()).toBeNull();
		expect(reasonOf(warn, "cimd_document_rejected")).toContain("unsupported_encoding");
	});

	it("refuses to be built without the composition's configuration, so core.outbound is never skipped", () => {
		expect(() =>
			// @ts-expect-error `config` is required.
			createClientIdMetadataDocumentResolver({ allowedScopes: [], allowedAudiences: [] }),
		).toThrow(TypeError);
		for (const config of [undefined, null, false, ""]) {
			expect(
				() =>
					createClientIdMetadataDocumentResolver({
						allowedScopes: [],
						allowedAudiences: [],
						// @ts-expect-error `config` is the composition's configuration object.
						config,
					}),
				String(config),
			).toThrow(/config/);
		}
		expect(() =>
			withClientIdMetadataDocuments(
				{ findById: async () => null, authenticate: async () => null },
				// @ts-expect-error `config` is required.
				{ allowedScopes: [], allowedAudiences: [] },
			),
		).toThrow(/config/);
		// A fetch substitute does not lift the requirement.
		expect(() =>
			createClientIdMetadataDocumentResolver({
				allowedScopes: [],
				allowedAudiences: [],
				// @ts-expect-error `config` is the composition's configuration object.
				config: undefined,
				fetch: fakeFetch([() => json(document())]).fetch,
			}),
		).toThrow(/config/);
	});

	it("builds its fetch from core.outbound when it is built, and refuses a malformed section then", () => {
		expect(() =>
			createClientIdMetadataDocumentResolver({
				allowedScopes: [],
				allowedAudiences: [],
				config: { core: { outbound: { allowedHost: ["client.example"] } } },
			}),
		).toThrow(/core\.outbound/);
	});
});

describe("revalidation and the stale window, through core's outbound policy", () => {
	const warmThen = (...later: Array<() => OutboundAnswer>) => {
		const clock = { now: 1_000_000 };
		const { fetch, exchanges } = outbound([
			() => jsonAnswer(document(), { "cache-control": "max-age=1", etag: '"v1"' }),
			...later,
		]);
		const { resolve, warn } = resolver({ fetch, now: () => clock.now });
		return { resolve, warn, exchanges, clock };
	};

	it("keeps the cached registration on a 304, whatever Content-Length the 304 states", async () => {
		const { resolve, exchanges, clock } = warmThen(() =>
			answer(304, { "content-length": "10000000", "cache-control": "max-age=30" }),
		);

		expect((await resolve())?.clientName).toBe("Acme Chat");
		clock.now += 2_000;
		expect((await resolve())?.clientName).toBe("Acme Chat");
		expect(exchanges).toHaveLength(2);
		expect(exchanges[1]?.headers["if-none-match"]).toBe('"v1"');
		clock.now += 20_000; // within the 30 s the 304 granted
		expect((await resolve())?.clientName).toBe("Acme Chat");
		expect(exchanges).toHaveLength(2);
	});

	it("serves the stale registration through a 503 whose body is over the cap and never arrives", async () => {
		const { resolve, warn, clock } = warmThen(() =>
			stalled(503, { "content-type": "application/json", "content-length": "10000000" }),
		);

		expect(await resolve()).not.toBeNull();
		clock.now += 2_000;
		expect(await resolve()).not.toBeNull();
		expect(warn).toHaveBeenCalledWith(expect.anything(), "cimd_document_fetch_failed");
	});

	it("evicts on a 404 whose body never arrives", async () => {
		const { resolve, warn, clock } = warmThen(() => stalled(404));

		expect(await resolve()).not.toBeNull();
		clock.now += 2_000;
		expect(await resolve()).toBeNull();
		expect(await resolve()).toBeNull();
		expect(warn).toHaveBeenCalledWith(expect.anything(), "cimd_document_rejected");
	});

	it("evicts on a refused destination, and rides out a failed resolution", async () => {
		const evicting = (() => {
			const clock = { now: 1_000_000 };
			let answered = 0;
			const { fetch } = outbound([() => jsonAnswer(document(), { "cache-control": "max-age=1" })], {
				lookup: async () => (answered++ === 0 ? ["93.184.216.34"] : ["10.0.0.5"]),
			});
			return { ...resolver({ fetch, now: () => clock.now }), clock };
		})();
		expect(await evicting.resolve()).not.toBeNull();
		evicting.clock.now += 2_000;
		expect(await evicting.resolve()).toBeNull();

		const riding = (() => {
			const clock = { now: 1_000_000 };
			let answered = 0;
			const { fetch } = outbound([() => jsonAnswer(document(), { "cache-control": "max-age=1" })], {
				lookup: async () => {
					if (answered++ === 0) return ["93.184.216.34"];
					throw Object.assign(new Error("lookup failed"), { code: "EAI_AGAIN" });
				},
			});
			return { ...resolver({ fetch, now: () => clock.now }), clock };
		})();
		expect(await riding.resolve()).not.toBeNull();
		riding.clock.now += 2_000;
		expect(await riding.resolve()).not.toBeNull();
		expect(riding.warn).toHaveBeenCalledWith(expect.anything(), "cimd_document_fetch_failed");
	});
});

describe("the host lists are read in core's host-list grammar", () => {
	const IDN_URL = "https://xn--bcher-kva.example/meta";
	const SUB_IDN_URL = "https://a.xn--bcher-kva.example/meta";

	it("matches an entry however it is spelled: Unicode or punycode, with or without the root dot", async () => {
		for (const [entry, id] of [
			["bücher.example", IDN_URL],
			["BÜCHER.example.", IDN_URL],
			["client.example.", CLIENT_URL],
			[".client.example.", CLIENT_URL],
		] as const) {
			const { resolve, calls, warn } = resolver({ deniedHosts: [entry] });
			expect(await resolve(id), entry).toBeNull();
			expect(calls, entry).toHaveLength(0);
			expect(warn, entry).toHaveBeenCalledWith(expect.anything(), "cimd_host_not_allowed");
		}
		const allowed = resolver({ allowedHosts: [".bücher.example"] }, [
			() => json(document({ client_id: SUB_IDN_URL })),
		]);
		expect(await allowed.resolve(SUB_IDN_URL)).not.toBeNull();
	});

	it("refuses a host with an empty label before any fetch", async () => {
		const { resolve, calls } = resolver();
		expect(await resolve("https://a..example/meta")).toBeNull();
		expect(calls).toHaveLength(0);
	});

	it("refuses to be built with an entry the grammar cannot read, naming the list", () => {
		for (const [list, entry] of [
			["allowedHosts", "*.example"],
			["deniedHosts", "https://client.example"],
			["deniedHosts", "client.example:443"],
		] as const) {
			expect(
				() =>
					createClientIdMetadataDocumentResolver({
						config: {},
						allowedScopes: [],
						allowedAudiences: [],
						[list]: [entry],
					}),
				entry,
			).toThrow(new RegExp(list));
		}
	});
});

describe("a deadline or cap above core.outbound's is said once, at construction", () => {
	const build = (over: Partial<ClientIdMetadataDocumentOptions>) => {
		const warn = vi.fn();
		const logger = { warn, info: vi.fn(), error: vi.fn(), debug: vi.fn() } as unknown as Logger;
		createClientIdMetadataDocumentResolver({
			allowedScopes: [],
			allowedAudiences: [],
			config: {},
			logger,
			...over,
		});
		return warn;
	};
	const cappedLines = (warn: ReturnType<typeof vi.fn>) =>
		warn.mock.calls.filter(([, event]) => event === "cimd_limit_capped");

	it("names both keys and the value in effect when maxBytes is above core.outbound.maxResponseBytes", () => {
		const warn = build({
			config: withOutbound({}, { maxResponseBytes: 4096 }),
			maxBytes: 8192,
		});

		expect(cappedLines(warn)).toEqual([
			[
				{
					limits: [
						{
							key: "oauth.clientIdMetadataDocuments.maxBytes",
							value: 8192,
							ceiling: "core.outbound.maxResponseBytes",
							effective: 4096,
						},
					],
				},
				"cimd_limit_capped",
			],
		]);
	});

	it("names both keys and the value in effect when timeoutMs is above core.outbound.timeoutMs", () => {
		const warn = build({ timeoutMs: 10_000 });

		expect(cappedLines(warn)).toEqual([
			[
				{
					limits: [
						{
							key: "oauth.clientIdMetadataDocuments.timeoutMs",
							value: 10_000,
							ceiling: "core.outbound.timeoutMs",
							effective: 5000,
						},
					],
				},
				"cimd_limit_capped",
			],
		]);
	});

	it("says both in one line when both are above", () => {
		const warn = build({ timeoutMs: 10_000, maxBytes: 100_000 });

		expect(cappedLines(warn)).toHaveLength(1);
		const [fields] = cappedLines(warn)[0] as [{ limits: Array<{ key: string }> }];
		expect(fields.limits.map((limit) => limit.key)).toEqual([
			"oauth.clientIdMetadataDocuments.timeoutMs",
			"oauth.clientIdMetadataDocuments.maxBytes",
		]);
	});

	it("says nothing for a deadline and cap equal to or below core.outbound's", () => {
		expect(cappedLines(build({}))).toEqual([]);
		expect(
			cappedLines(
				build({
					config: withOutbound({}, { timeoutMs: 3000, maxResponseBytes: 4096 }),
					timeoutMs: 3000,
					maxBytes: 4096,
				}),
			),
		).toEqual([]);
		expect(cappedLines(build({ timeoutMs: 1000, maxBytes: 1024 }))).toEqual([]);
	});

	it("says it once per configuration, however many resolvers are built from it", () => {
		const config = withOutbound({}, { maxResponseBytes: 4096 });
		expect(cappedLines(build({ config, maxBytes: 8192 }))).toHaveLength(1);
		expect(cappedLines(build({ config, maxBytes: 8192 }))).toEqual([]);
	});

	it("says each different capping of the same configuration", () => {
		const config = withOutbound({}, { maxResponseBytes: 4096 });
		expect(cappedLines(build({ config, maxBytes: 8192 }))).toHaveLength(1);
		expect(cappedLines(build({ config, timeoutMs: 10_000, maxBytes: 1024 }))).toHaveLength(1);
	});

	it("says it again when a logger could not write it", () => {
		const config = withOutbound({}, { maxResponseBytes: 4096 });
		const failing = {
			warn: () => {
				throw new Error("log sink down");
			},
			info: vi.fn(),
			error: vi.fn(),
			debug: vi.fn(),
		} as unknown as Logger;
		expect(() => build({ config, maxBytes: 8192, logger: failing })).toThrow("log sink down");
		expect(cappedLines(build({ config, maxBytes: 8192 }))).toHaveLength(1);
	});

	it("says nothing when a fetch substitute replaces the policy", () => {
		const warn = build({ maxBytes: 100_000, fetch: fakeFetch([]).fetch });

		expect(cappedLines(warn)).toEqual([]);
	});
});
