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
 * The Client ID Metadata Document fallback asks core's client-record
 * boundary first and resolves a document only when no client is registered
 * under the id. A registration the boundary refuses rejects the lookup with
 * core's refusal and is never replaced by a document, whether the fallback's
 * own boundary refuses it or a boundary behind a layer it reads through
 * does, another fallback included; a repository that cannot answer is an
 * outage, never answered from the document cache.
 */

import {
	type ClientRepository,
	isClientRecordRefused,
	type Logger,
	type PublicClient,
	validatedClientRepository,
} from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import {
	type ClientIdMetadataDocumentOptions,
	isClientIdMetadataDocumentClient,
	withClientIdMetadataDocuments,
} from "#/clients/clientIdMetadataDocument.mjs";

const CLIENT_URL = "https://client.example/oauth/client-metadata.json";

const document = (): Record<string, unknown> => ({
	client_id: CLIENT_URL,
	client_name: "Acme Chat",
	redirect_uris: ["https://client.example/cb"],
	grant_types: ["authorization_code"],
	response_types: ["code"],
	token_endpoint_auth_method: "none",
});

const json = (body: unknown, headers: Record<string, string> = {}, status = 200): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json", ...headers },
	});

/** A fake `fetch` answering one canned response per call, counting the calls. */
const fakeFetch = (responses: Array<() => Response>) => {
	const calls: string[] = [];
	const impl = (async (input: string | URL | Request) => {
		calls.push(String(input));
		const next = responses.shift();
		if (next === undefined) throw new Error("fakeFetch: no response queued");
		return next();
	}) as typeof fetch;
	return { fetch: impl, calls };
};

const recordingLogger = () =>
	({ warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() }) as unknown as Logger & {
		warn: ReturnType<typeof vi.fn>;
	};

/** A registered client under the document URL, as a deployment's repository holds it. */
const registered = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
	clientId: CLIENT_URL,
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedRedirectUris: ["https://client.example/registered-cb"],
	allowedScopes: ["read"],
	allowedGrantTypes: [],
	firstParty: true,
	...over,
});

/** A repository whose answer for the URL is whatever `answer` currently holds. */
const switchable = (initial: () => unknown) => {
	let answer = initial;
	const repository: ClientRepository = {
		findById: async (id) => (id === CLIENT_URL ? (answer() as PublicClient | null) : null),
		authenticate: async () => null,
	};
	return {
		repository,
		set: (next: () => unknown) => {
			answer = next;
		},
	};
};

/** What a lookup rejected with, or `undefined` when it resolved. */
const rejectionOf = (lookup: Promise<unknown>): Promise<unknown> =>
	lookup.then(
		() => undefined,
		(error: unknown) => error,
	);

const cimd = (
	inner: ClientRepository,
	fetchImpl: typeof fetch,
	over: Partial<ClientIdMetadataDocumentOptions> = {},
) =>
	withClientIdMetadataDocuments(inner, {
		allowedScopes: ["read"],
		allowedAudiences: [],
		fetch: fetchImpl,
		lookup: async () => ["93.184.216.34"],
		...over,
	});

describe("a refused registration never falls through to a document", () => {
	it("rejects a URL-shaped registered id with a malformed record with core's refusal, and never fetches", async () => {
		// The registration the boundary refuses (an empty client name) once read
		// as "not registered", and the document at the same URL — authored by
		// whoever serves it — stood in: a public client with the document's
		// redirect URIs in place of a confidential one allowed no grant.
		const { fetch, calls } = fakeFetch([() => json(document())]);
		const logger = recordingLogger();
		const { repository } = switchable(() => registered({ clientName: "" }));
		const repo = cimd(repository, fetch, { logger });
		expect(isClientRecordRefused(await rejectionOf(repo.findById(CLIENT_URL)))).toBe(true);
		expect(calls).toEqual([]);
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ step: "find", clientId: CLIENT_URL }),
			"client_record_refused",
		);
	});

	it("refuses a registration under another id, an answer that is not an object, and a value JSON does not hold alike", async () => {
		for (const answer of [
			() => registered({ clientId: "https://client.example/other" }),
			() => "client",
			() => registered({ clientName: new Date(0) }),
		]) {
			const { fetch, calls } = fakeFetch([() => json(document())]);
			const { repository } = switchable(answer);
			const lookup = cimd(repository, fetch, { logger: recordingLogger() }).findById(CLIENT_URL);
			expect(isClientRecordRefused(await rejectionOf(lookup))).toBe(true);
			expect(calls).toEqual([]);
		}
	});

	describe("refused by a boundary behind a layer the fallback reads through", () => {
		/** A cache of the lookups' promises, as a memoising layer keeps them. */
		const promiseCache = (inner: ClientRepository): ClientRepository => {
			const found = new Map<string, Promise<PublicClient | null>>();
			return {
				findById: (clientId) => {
					const cached = found.get(clientId) ?? inner.findById(clientId);
					found.set(clientId, cached);
					return cached;
				},
				authenticate: (clientId, secret) => inner.authenticate(clientId, secret),
			};
		};
		const LAYERS: ReadonlyArray<readonly [string, (inner: ClientRepository) => ClientRepository]> =
			[
				["a spread copy", (inner) => ({ ...inner })],
				[
					"an async forwarder",
					(inner) => ({
						findById: async (clientId) => await inner.findById(clientId),
						authenticate: async (clientId, secret) => await inner.authenticate(clientId, secret),
					}),
				],
				["a promise cache", promiseCache],
			];

		for (const [name, layer] of LAYERS) {
			it(`never fetches through ${name}, letting the refusal through`, async () => {
				const { fetch, calls } = fakeFetch([() => json(document())]);
				const logger = recordingLogger();
				const { repository } = switchable(() => registered({ clientName: "" }));
				const repo = cimd(layer(validatedClientRepository(repository, { logger })), fetch, {
					logger: recordingLogger(),
				});
				const rejection = await repo.findById(CLIENT_URL).then(
					() => undefined,
					(error: unknown) => error,
				);
				expect(isClientRecordRefused(rejection)).toBe(true);
				expect(calls).toEqual([]);
				expect(
					logger.warn.mock.calls.filter(([, message]) => message === "client_record_refused"),
				).toHaveLength(1);
			});
		}

		it("never answers the document cached from before the registration went bad", async () => {
			const { fetch, calls } = fakeFetch([
				() => json(document(), { "cache-control": "max-age=600" }),
			]);
			const state = switchable(() => null);
			const repo = cimd(
				{ ...validatedClientRepository(state.repository, { logger: recordingLogger() }) },
				fetch,
				{ logger: recordingLogger() },
			);
			expect(isClientIdMetadataDocumentClient(await repo.findById(CLIENT_URL))).toBe(true);
			state.set(() => registered({ firstParty: "true" }));
			const rejection = await repo.findById(CLIENT_URL).then(
				() => undefined,
				(error: unknown) => error,
			);
			expect(isClientRecordRefused(rejection)).toBe(true);
			expect(calls).toHaveLength(1);
		});

		it("never fetches through a forwarder over another fallback that refused the registration", async () => {
			// The outer fallback cannot see the inner one behind the forwarder:
			// only the inner one's rejection keeps the outer one from fetching.
			const inner = fakeFetch([() => json(document())]);
			const outer = fakeFetch([() => json(document())]);
			const logger = recordingLogger();
			const { repository } = switchable(() => registered({ clientName: "" }));
			const first = cimd(repository, inner.fetch, { logger });
			const forwarder: ClientRepository = {
				findById: async (clientId) => await first.findById(clientId),
				authenticate: async (clientId, secret) => await first.authenticate(clientId, secret),
			};
			const repo = cimd(forwarder, outer.fetch, { logger: recordingLogger() });
			expect(isClientRecordRefused(await rejectionOf(repo.findById(CLIENT_URL)))).toBe(true);
			expect(inner.calls).toEqual([]);
			expect(outer.calls).toEqual([]);
			expect(
				logger.warn.mock.calls.filter(([, message]) => message === "client_record_refused"),
			).toHaveLength(1);
		});
	});

	it("answers a lookup that finds the registration refused without joining a document fetch already in flight", async () => {
		// Lookup A saw no registration and is fetching the document; the
		// registration then turns refused. Lookup B reads the refusal and
		// rejects at once, never waiting on or taking A's document.
		let release: () => void = () => {};
		const paused = new Promise<void>((resolve) => {
			release = resolve;
		});
		const calls: string[] = [];
		const fetchImpl = (async (input: string | URL | Request) => {
			calls.push(String(input));
			await paused;
			return json(document());
		}) as typeof fetch;
		const state = switchable(() => null);
		const repo = cimd(state.repository, fetchImpl, { logger: recordingLogger() });
		const lookupA = repo.findById(CLIENT_URL);
		await vi.waitFor(() => expect(calls).toHaveLength(1));
		state.set(() => registered({ clientName: "" }));
		const lookupB = rejectionOf(repo.findById(CLIENT_URL));
		const first = await Promise.race([
			lookupB.then((rejection) => ({ who: "B", refused: isClientRecordRefused(rejection) })),
			lookupA.then(() => ({ who: "A", refused: false })),
		]);
		expect(first).toEqual({ who: "B", refused: true });
		release();
		// A answers what it saw when it started: absent, so the document.
		expect(isClientIdMetadataDocumentClient(await lookupA)).toBe(true);
		expect(calls).toHaveLength(1);
	});

	it("refuses even when the document is cached from before the registration went bad", async () => {
		const { fetch, calls } = fakeFetch([
			() => json(document(), { "cache-control": "max-age=600" }),
		]);
		const state = switchable(() => null);
		const repo = cimd(state.repository, fetch, { logger: recordingLogger() });
		const resolved = await repo.findById(CLIENT_URL);
		expect(isClientIdMetadataDocumentClient(resolved)).toBe(true);
		state.set(() => registered({ firstParty: "true" }));
		expect(isClientRecordRefused(await rejectionOf(repo.findById(CLIENT_URL)))).toBe(true);
		expect(calls).toHaveLength(1);
	});
});

describe("an absent registration still resolves the document", () => {
	it("resolves the document as before, the resolver's own object rather than core's copy, recognised as a document client", async () => {
		const { fetch, calls } = fakeFetch([() => json(document())]);
		const { repository } = switchable(() => null);
		const repo = cimd(repository, fetch);
		const client = await repo.findById(CLIENT_URL);
		expect(client?.clientId).toBe(CLIENT_URL);
		expect(client?.firstParty).toBe(false);
		expect(isClientIdMetadataDocumentClient(client)).toBe(true);
		// Not passed through core's boundary, whose answers are frozen copies:
		// the same object again from the resolver's cache, unfrozen.
		expect(Object.isFrozen(client)).toBe(false);
		expect(await repo.findById(CLIENT_URL)).toBe(client);
		expect(calls).toHaveLength(1);
	});

	it("answers a valid registration from the repository, validated, and never fetches", async () => {
		const { fetch, calls } = fakeFetch([() => json(document())]);
		const { repository } = switchable(() => registered());
		const client = await cimd(repository, fetch).findById(CLIENT_URL);
		expect(client?.firstParty).toBe(true);
		expect(client?.allowedGrantTypes).toEqual([]);
		expect(isClientIdMetadataDocumentClient(client)).toBe(false);
		expect(Object.isFrozen(client)).toBe(true);
		expect(calls).toEqual([]);
	});
});

describe("a repository that cannot answer is an outage, never a document", () => {
	const outage = new Error("connection reset");

	it("lets the outage through with a warm document cache", async () => {
		const { fetch, calls } = fakeFetch([
			() => json(document(), { "cache-control": "max-age=600" }),
		]);
		const state = switchable(() => null);
		const repo = cimd(state.repository, fetch);
		expect(await repo.findById(CLIENT_URL)).not.toBeNull();
		state.set(() => {
			throw outage;
		});
		await expect(repo.findById(CLIENT_URL)).rejects.toBe(outage);
		expect(calls).toHaveLength(1);
	});

	it("lets the outage through inside the stale-if-error window", async () => {
		const clock = { now: 1_000_000 };
		const { fetch, calls } = fakeFetch([
			() => json(document(), { "cache-control": "max-age=1" }),
			() => json({ error: "down" }, {}, 503),
		]);
		const state = switchable(() => null);
		const repo = cimd(state.repository, fetch, { now: () => clock.now, staleIfErrorMs: 60_000 });
		expect(await repo.findById(CLIENT_URL)).not.toBeNull();
		clock.now += 2_000;
		// The document's server fails: the stale registration rides it out.
		expect(await repo.findById(CLIENT_URL)).not.toBeNull();
		expect(calls).toHaveLength(2);
		// The repository fails: an outage, not the stale document.
		state.set(() => {
			throw outage;
		});
		await expect(repo.findById(CLIENT_URL)).rejects.toBe(outage);
		expect(calls).toHaveLength(2);
	});

	it("lets the outage through over a remembered document refusal", async () => {
		const { fetch, calls } = fakeFetch([() => json({ error: "gone" }, {}, 404)]);
		const state = switchable(() => null);
		const repo = cimd(state.repository, fetch, {
			negativeCacheMs: 60_000,
			logger: recordingLogger(),
		});
		expect(await repo.findById(CLIENT_URL)).toBeNull();
		state.set(() => {
			throw outage;
		});
		await expect(repo.findById(CLIENT_URL)).rejects.toBe(outage);
		expect(calls).toHaveLength(1);
	});
});

describe("a fallback over one boundary", () => {
	it("rejects a registration refused through a boundary built before the fallback, and never fetches", async () => {
		// The composition core's slot wrap will produce: the fallback over a
		// repository already behind the boundary, read as the same boundary.
		const { fetch, calls } = fakeFetch([() => json(document())]);
		const logger = recordingLogger();
		const { repository } = switchable(() => registered({ clientName: "" }));
		const repo = cimd(validatedClientRepository(repository, { logger }), fetch);
		expect(isClientRecordRefused(await rejectionOf(repo.findById(CLIENT_URL)))).toBe(true);
		expect(calls).toEqual([]);
		expect(
			logger.warn.mock.calls.filter(([, message]) => message === "client_record_refused"),
		).toHaveLength(1);
	});

	it("says nothing of a refused registration when given no logger, as it says nothing of a refused document", async () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		try {
			const { fetch } = fakeFetch([]);
			const { repository } = switchable(() => registered({ clientName: "" }));
			const lookup = cimd(repository, fetch).findById(CLIENT_URL);
			expect(isClientRecordRefused(await rejectionOf(lookup))).toBe(true);
			expect(warn).not.toHaveBeenCalled();
		} finally {
			warn.mockRestore();
		}
	});

	it("authenticates through the boundary, a refused record rejecting with the refusal", async () => {
		const { fetch, calls } = fakeFetch([]);
		const repository: ClientRepository = {
			findById: async () => null,
			authenticate: async () => registered({ firstParty: "true" }) as unknown as PublicClient,
		};
		const repo = cimd(repository, fetch, { logger: recordingLogger() });
		const rejection = await repo.authenticate(CLIENT_URL, "secret").then(
			() => undefined,
			(error: unknown) => error,
		);
		expect(isClientRecordRefused(rejection)).toBe(true);
		expect(calls).toEqual([]);
	});
});
