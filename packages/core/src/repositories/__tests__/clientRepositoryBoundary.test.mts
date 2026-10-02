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
 * The boundary where a `ClientRepository`'s answer enters the system: each
 * record is read by name once, into a plain copy, and held to the
 * registration schema. A record that fails is answered as no client, with a
 * warn naming the client id and the reasons; a read that throws is the
 * store's outage and is let through as it was thrown.
 */

import { describe, expect, it, vi } from "vitest";
import type { ClientRepository, PublicClient } from "#/repositories/ClientRepository.mjs";
import { validatedClientRepository } from "#/repositories/clientRepositoryBoundary.mjs";
import { InMemoryClientRepository } from "#/repositories/InMemoryClientRepository.mjs";
import { clientEntries } from "#/testing/index.mjs";

const CLIENT_ID = "client-1";

/** A record every rule of the registration schema accepts, every field set. */
const validRecord = (): Record<string, unknown> => ({
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedRedirectUris: ["https://rp.example/cb"],
	allowedScopes: ["openid", "profile"],
	defaultScopes: ["openid"],
	allowedAudiences: ["https://api.example"],
	allowedGrantTypes: ["authorization_code", "refresh_token"],
	postLogoutRedirectUris: ["https://rp.example/bye"],
	backchannelLogoutUri: "https://rp.example/backchannel",
	backchannelLogoutSessionRequired: false,
	frontchannelLogoutUri: "https://rp.example/frontchannel",
	frontchannelLogoutSessionRequired: false,
	allowedAzpForFederationToken: true,
	allowedFederationGrantConnections: ["calendar"],
	federationGrantRedirectUris: ["https://rp.example/grant"],
	senderConstrained: { required: true, methods: ["dpop"] },
	firstParty: true,
	clientName: "Relying Party",
	clientUri: "https://rp.example",
	allowPlainPkce: false,
});

/** The fields `validRecord` sets: `PublicClient`'s but the two key sources, never `clientSecret`. */
const RECORD_FIELDS = Object.keys(validRecord());

/** Every field `PublicClient` declares: what the boundary reads, set or not, and nothing else. */
const DECLARED_FIELDS = [...RECORD_FIELDS, "jwks", "jwksUri"];

const repositoryAnswering = (record: unknown): ClientRepository => ({
	findById: async () => record as PublicClient | null,
	authenticate: async () => record as PublicClient | null,
});

const recordingLogger = () => ({ warn: vi.fn() });

/**
 * An entity as an ORM hands it out: its columns in an internal record, each
 * surfaced by a getter on the prototype, beside internals of its own.
 */
function ormEntity(columns: Record<string, unknown>, reads?: Map<string, number>): object {
	class Entity {
		dataValues: Record<string, unknown>;
		isNewRecord = false;
		constructor(values: Record<string, unknown>) {
			this.dataValues = values;
		}
	}
	for (const column of Object.keys(columns)) {
		Object.defineProperty(Entity.prototype, column, {
			get(this: Entity) {
				reads?.set(column, (reads.get(column) ?? 0) + 1);
				return this.dataValues[column];
			},
			enumerable: false,
			configurable: true,
		});
	}
	return new Entity({ ...columns });
}

/** A list whose first index is missing and whose second holds `value`. */
const listWithHole = (value: string): string[] => {
	const list: string[] = [];
	list[1] = value;
	return list;
};

/** A list column as an ORM hands it out: an Array subclass with internals of its own. */
class ListColumn<T> extends Array<T> {
	readonly dirty = false;
}

describe("validatedClientRepository — a valid record", () => {
	it("is answered as a plain copy holding what the record holds, the schema's defaults filled", async () => {
		const record = validRecord();
		const boundary = validatedClientRepository(repositoryAnswering(record));
		const client = await boundary.findById(CLIENT_ID);
		expect(client).toEqual(record);
		expect(client).not.toBe(record);
		expect(client?.allowedRedirectUris).not.toBe(record.allowedRedirectUris);
	});

	it("fills the defaults the registration schema fills, as the bundled repository does", async () => {
		const boundary = validatedClientRepository(
			repositoryAnswering({ clientId: CLIENT_ID, tokenEndpointAuthMethod: "none" }),
		);
		const bundled = new InMemoryClientRepository(
			clientEntries([[CLIENT_ID, { tokenEndpointAuthMethod: "none" }]]),
		);
		expect(await boundary.findById(CLIENT_ID)).toEqual(await bundled.findById(CLIENT_ID));
	});

	it("answers authenticate's record through the same check", async () => {
		const boundary = validatedClientRepository(repositoryAnswering(validRecord()));
		expect(await boundary.authenticate(CLIENT_ID, "secret")).toEqual(validRecord());
	});

	it("answers the bundled repository's records unchanged", async () => {
		const bundled = new InMemoryClientRepository(
			clientEntries([
				[
					CLIENT_ID,
					{
						tokenEndpointAuthMethod: "client_secret_post",
						clientSecret: "s3cret-s3cret",
						allowedRedirectUris: ["https://rp.example/cb"],
						allowedScopes: ["openid"],
					},
				],
			]),
		);
		const boundary = validatedClientRepository(bundled);
		expect(await boundary.findById(CLIENT_ID)).toEqual(await bundled.findById(CLIENT_ID));
		expect(await boundary.authenticate(CLIENT_ID, "s3cret-s3cret")).toEqual(
			await bundled.authenticate(CLIENT_ID, "s3cret-s3cret"),
		);
	});

	it("accepts an ORM entity whose columns are prototype getters and whose lists are Array subclasses", async () => {
		const columns = {
			...validRecord(),
			allowedRedirectUris: ListColumn.from(["https://rp.example/cb"]),
			allowedScopes: ListColumn.from(["openid", "profile"]),
		};
		const logger = recordingLogger();
		const boundary = validatedClientRepository(repositoryAnswering(ormEntity(columns)), {
			logger,
		});
		const client = await boundary.findById(CLIENT_ID);
		expect(client).toEqual(validRecord());
		expect(Object.getPrototypeOf(client?.allowedScopes)).toBe(Array.prototype);
		expect(client).not.toHaveProperty("dataValues");
		expect(client).not.toHaveProperty("isNewRecord");
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it("reads each field once, by name, never the secret, and nothing after it answers", async () => {
		const reads = new Map<string, number>();
		const entity = ormEntity({ ...validRecord(), clientSecret: "never-read" }, reads);
		const boundary = validatedClientRepository(repositoryAnswering(entity));
		const client = await boundary.findById(CLIENT_ID);
		expect(Object.fromEntries(reads)).toEqual(
			Object.fromEntries(RECORD_FIELDS.map((field) => [field, 1])),
		);
		// What it answers is its own: reading it reads nothing of the record.
		void JSON.stringify(client);
		expect(Object.fromEntries(reads)).toEqual(
			Object.fromEntries(RECORD_FIELDS.map((field) => [field, 1])),
		);
		expect(client).not.toHaveProperty("clientSecret");
	});

	it("reads each of the 22 declared fields of a Proxy-backed record once, and nothing else of it", async () => {
		const reads = new Map<PropertyKey, number>();
		const otherTraps: string[] = [];
		const target = {
			...validRecord(),
			tokenEndpointAuthMethod: "private_key_jwt",
			jwks: {
				keys: [{ kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" }],
			},
			clientSecret: "never-read",
			internalNote: "never-read",
		};
		const record = new Proxy(target, {
			get(source, key, receiver) {
				reads.set(key, (reads.get(key) ?? 0) + 1);
				return Reflect.get(source, key, receiver);
			},
			has: (source, key) => {
				otherTraps.push(`has ${String(key)}`);
				return Reflect.has(source, key);
			},
			ownKeys: (source) => {
				otherTraps.push("ownKeys");
				return Reflect.ownKeys(source);
			},
			getOwnPropertyDescriptor: (source, key) => {
				otherTraps.push(`getOwnPropertyDescriptor ${String(key)}`);
				return Reflect.getOwnPropertyDescriptor(source, key);
			},
		});
		const boundary = validatedClientRepository(repositoryAnswering(record));
		expect((await boundary.lookupClient(CLIENT_ID)).outcome).toBe("found");
		expect(DECLARED_FIELDS).toHaveLength(22);
		// `then` is read once by the promise the repository answers with, as any
		// async answer is, before the boundary sees the record.
		expect(reads.get("then")).toBe(1);
		reads.delete("then");
		expect(Object.fromEntries(reads)).toEqual(
			Object.fromEntries(DECLARED_FIELDS.map((field) => [field, 1])),
		);
		expect(otherTraps).toEqual([]);
	});

	it("copies a list in index order, whatever order a Proxy enumerates its keys in", async () => {
		// The first audience is a token's default `aud`: the copy must not reorder it.
		const audiences = new Proxy(["https://first.example", "https://second.example"], {
			ownKeys: (target) => Reflect.ownKeys(target).reverse(),
		});
		const boundary = validatedClientRepository(
			repositoryAnswering({ ...validRecord(), allowedAudiences: audiences }),
		);
		const client = await boundary.findById(CLIENT_ID);
		expect(client?.allowedAudiences).toEqual(["https://first.example", "https://second.example"]);
	});

	it("drops what the record holds beyond the fields PublicClient declares, the secret included", async () => {
		const boundary = validatedClientRepository(
			repositoryAnswering({ ...validRecord(), clientSecret: "leaked", internalNote: "x" }),
		);
		const client = await boundary.findById(CLIENT_ID);
		expect(client).toEqual(validRecord());
	});
});

describe("validatedClientRepository — a malformed record is answered as no client", () => {
	const MALFORMED: ReadonlyArray<readonly [string, Record<string, unknown>, string]> = [
		["an unknown auth method", { tokenEndpointAuthMethod: "magic" }, "tokenEndpointAuthMethod"],
		["a missing auth method", { tokenEndpointAuthMethod: undefined }, "tokenEndpointAuthMethod"],
		[
			"a redirect URI with an executable scheme",
			{ allowedRedirectUris: ["javascript:alert(1)"] },
			"allowedRedirectUris",
		],
		[
			"a redirect URI list that is a string",
			{ allowedRedirectUris: "https://rp.example/cb" },
			"allowedRedirectUris",
		],
		[
			"a post-logout redirect URI with a fragment",
			{ postLogoutRedirectUris: ["https://rp.example/bye#x"] },
			"postLogoutRedirectUris",
		],
		[
			"a front-channel logout URI that is not http(s)",
			{ frontchannelLogoutUri: "javascript:alert(1)" },
			"frontchannelLogoutUri",
		],
		[
			"a back-channel logout URI that is not http(s)",
			{ backchannelLogoutUri: "ftp://rp.example/bc" },
			"backchannelLogoutUri",
		],
		["a client URI that is not http(s)", { clientUri: "javascript:alert(1)" }, "clientUri"],
		[
			"a federation-grant return URI carrying a reserved parameter",
			{ federationGrantRedirectUris: ["https://rp.example/grant?grant_id=1"] },
			"federationGrantRedirectUris",
		],
		[
			"a federation-grant connection that is not a name",
			{ allowedFederationGrantConnections: ["not a name"] },
			"allowedFederationGrantConnections",
		],
		["default scopes outside the allowed ones", { defaultScopes: ["admin"] }, "defaultScopes"],
		["an empty audience", { allowedAudiences: [""] }, "allowedAudiences"],
		["a grant type that is not a string", { allowedGrantTypes: [1] }, "allowedGrantTypes"],
		["firstParty as the string true", { firstParty: "true" }, "firstParty"],
		["allowPlainPkce as a number", { allowPlainPkce: 1 }, "allowPlainPkce"],
		[
			"a logout session flag that is not a boolean",
			{ backchannelLogoutSessionRequired: "yes" },
			"backchannelLogoutSessionRequired",
		],
		["an empty client name", { clientName: "" }, "clientName"],
		[
			"a sender constraint required with no methods",
			{ senderConstrained: { required: true, methods: [] } },
			"senderConstrained",
		],
		["keys for a method that takes none", { jwksUri: "https://rp.example/jwks" }, "jwksUri"],
		[
			"private key material in jwks",
			{
				tokenEndpointAuthMethod: "private_key_jwt",
				jwks: { keys: [{ kty: "RSA", n: "x", e: "AQAB", d: "private" }] },
			},
			"jwks",
		],
		[
			"a federation-grant field on a public client",
			{ tokenEndpointAuthMethod: "none", allowedFederationGrantConnections: ["calendar"] },
			"allowedFederationGrantConnections",
		],
		["a value that is not plain data", { clientName: new Date(0) }, "clientName"],
		["a number that is not finite", { allowedScopes: [Number.NaN] }, "allowedScopes"],
		["a list with a hole", { allowedScopes: listWithHole("openid") }, "allowedScopes"],
		["a record under another client id", { clientId: "client-2" }, "clientId"],
		["a record with no client id", { clientId: undefined }, "clientId"],
	];

	for (const [name, change, field] of MALFORMED) {
		it(`refuses ${name}, on findById and on authenticate`, async () => {
			const record = { ...validRecord(), ...change };
			const logger = recordingLogger();
			const boundary = validatedClientRepository(repositoryAnswering(record), { logger });
			expect(await boundary.findById(CLIENT_ID)).toBeNull();
			expect(await boundary.authenticate(CLIENT_ID, "secret")).toBeNull();
			expect(logger.warn).toHaveBeenCalledTimes(2);
			const [[findLine, findMessage], [authLine]] = logger.warn.mock.calls as [
				[Record<string, unknown>, string],
				[Record<string, unknown>, string],
			];
			expect(findMessage).toBe("client_record_refused");
			expect(findLine).toMatchObject({ step: "find", clientId: CLIENT_ID });
			expect(authLine).toMatchObject({ step: "authenticate", clientId: CLIENT_ID });
			const reasons = findLine.reasons as string[];
			const naming = new RegExp(`^${field}[.:]`);
			expect(
				reasons.some((reason) => naming.test(reason)),
				reasons.join("; "),
			).toBe(true);
		});
	}

	it("refuses an answer that is not an object", async () => {
		for (const answer of ["client-1", 42, true, [validRecord()]]) {
			const logger = recordingLogger();
			const boundary = validatedClientRepository(repositoryAnswering(answer), { logger });
			expect(await boundary.findById(CLIENT_ID)).toBeNull();
			expect(logger.warn).toHaveBeenCalledWith(
				{ step: "find", clientId: CLIENT_ID, reasons: ["not an object"] },
				"client_record_refused",
			);
		}
	});

	it("logs the client id and the reasons, never the record", async () => {
		const logger = recordingLogger();
		const record = { ...validRecord(), clientSecret: "do-not-log-me", firstParty: "true" };
		const boundary = validatedClientRepository(repositoryAnswering(record), { logger });
		await boundary.findById(CLIENT_ID);
		const line = JSON.stringify(logger.warn.mock.calls);
		expect(line).not.toContain("do-not-log-me");
		expect(line).not.toContain("Relying Party");
		expect(Object.keys(logger.warn.mock.calls[0]?.[0] ?? {}).sort()).toEqual([
			"clientId",
			"reasons",
			"step",
		]);
	});

	it("refuses a record whose id no request could name, as a registered id is refused at boot", async () => {
		for (const clientId of ["a\nb", "a\u0000b", "a\u007fb", "x".repeat(257)]) {
			const logger = recordingLogger();
			const boundary = validatedClientRepository(
				repositoryAnswering({ ...validRecord(), clientId }),
				{ logger },
			);
			const lookup = await boundary.lookupClient(clientId);
			expect(lookup.outcome, JSON.stringify(clientId)).toBe("refused");
			expect(
				lookup.outcome === "refused" && lookup.reasons.some((r) => r.startsWith("clientId:")),
			).toBe(true);
		}
		const longest = validatedClientRepository(
			repositoryAnswering({ ...validRecord(), clientId: "x".repeat(256) }),
		);
		expect((await longest.lookupClient("x".repeat(256))).outcome).toBe("found");
	});

	it("sanitises the client id it logs, the client's own input", async () => {
		const logger = recordingLogger();
		const refusing = validatedClientRepository(
			repositoryAnswering({ ...validRecord(), clientId: "a\nb" }),
			{ logger },
		);
		expect(await refusing.findById("a\nb")).toBeNull();
		expect(logger.warn.mock.calls[0]?.[0]).toMatchObject({ clientId: "a?b" });
	});

	it("keeps ten reasons and counts them all when a record breaks more rules", async () => {
		const logger = recordingLogger();
		const boundary = validatedClientRepository(
			repositoryAnswering({
				...validRecord(),
				allowedRedirectUris: Array.from({ length: 12 }, (_, i) => `javascript:alert(${i})`),
			}),
			{ logger },
		);
		const lookup = await boundary.lookupClient(CLIENT_ID);
		expect(lookup.outcome === "refused" && lookup.reasons.length).toBe(12);
		const [line] = logger.warn.mock.calls[0] as [Record<string, unknown>];
		expect(line.reasons).toHaveLength(10);
		expect(line.reasonCount).toBe(12);
	});

	it("refuses a function answered as the record", async () => {
		const logger = recordingLogger();
		const record = Object.assign(() => {}, validRecord());
		const boundary = validatedClientRepository(repositoryAnswering(record), { logger });
		expect(await boundary.lookupClient(CLIENT_ID)).toEqual({
			outcome: "refused",
			reasons: ["not an object"],
		});
		expect(await boundary.findById(CLIENT_ID)).toBeNull();
	});

	it("answers no record as no client, silently", async () => {
		for (const answer of [null, undefined]) {
			const logger = recordingLogger();
			const boundary = validatedClientRepository(repositoryAnswering(answer), { logger });
			expect(await boundary.findById(CLIENT_ID)).toBeNull();
			expect(await boundary.authenticate(CLIENT_ID, "secret")).toBeNull();
			expect(logger.warn).not.toHaveBeenCalled();
		}
	});
});

describe("validatedClientRepository — a read that throws is the store's outage", () => {
	it("lets a getter's throw through as it was thrown, for the caller to answer 503", async () => {
		const outage = new Error("connection reset");
		const record = Object.defineProperty({ ...validRecord() }, "allowedScopes", {
			get() {
				throw outage;
			},
		});
		const logger = recordingLogger();
		const boundary = validatedClientRepository(repositoryAnswering(record), { logger });
		await expect(boundary.findById(CLIENT_ID)).rejects.toBe(outage);
		await expect(boundary.authenticate(CLIENT_ID, "secret")).rejects.toBe(outage);
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it("lets the repository's own throw through", async () => {
		const outage = new Error("store down");
		const boundary = validatedClientRepository({
			findById: async () => {
				throw outage;
			},
			authenticate: async () => {
				throw outage;
			},
		});
		await expect(boundary.findById(CLIENT_ID)).rejects.toBe(outage);
		await expect(boundary.authenticate(CLIENT_ID, "secret")).rejects.toBe(outage);
	});
});

describe("validatedClientRepository — lookupClient tells refused from absent", () => {
	it("answers a valid record found, as findById answers it", async () => {
		const boundary = validatedClientRepository(repositoryAnswering(validRecord()));
		const lookup = await boundary.lookupClient(CLIENT_ID);
		expect(lookup).toEqual({ outcome: "found", client: await boundary.findById(CLIENT_ID) });
	});

	it("answers a record it refuses refused, with the reasons, and warns once", async () => {
		const logger = recordingLogger();
		const boundary = validatedClientRepository(
			repositoryAnswering({ ...validRecord(), firstParty: "true" }),
			{ logger },
		);
		const lookup = await boundary.lookupClient(CLIENT_ID);
		expect(lookup.outcome).toBe("refused");
		expect(
			lookup.outcome === "refused" && lookup.reasons.some((r) => r.startsWith("firstParty:")),
		).toBe(true);
		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(logger.warn.mock.calls[0]?.[0]).toMatchObject({ step: "find", clientId: CLIENT_ID });
	});

	it("answers a record under another id refused, never absent", async () => {
		const boundary = validatedClientRepository(
			repositoryAnswering({ ...validRecord(), clientId: "CLIENT-1" }),
			{ logger: recordingLogger() },
		);
		expect(await boundary.lookupClient(CLIENT_ID)).toEqual({
			outcome: "refused",
			reasons: ["clientId: not the id that was looked up"],
		});
	});

	it("answers an answer that is not an object refused, never absent", async () => {
		const boundary = validatedClientRepository(repositoryAnswering("client-1"), {
			logger: recordingLogger(),
		});
		expect(await boundary.lookupClient(CLIENT_ID)).toEqual({
			outcome: "refused",
			reasons: ["not an object"],
		});
	});

	it("answers no record absent, silently", async () => {
		for (const answer of [null, undefined]) {
			const logger = recordingLogger();
			const boundary = validatedClientRepository(repositoryAnswering(answer), { logger });
			expect(await boundary.lookupClient(CLIENT_ID)).toEqual({ outcome: "absent" });
			expect(logger.warn).not.toHaveBeenCalled();
		}
	});

	it("lets a throwing read through, neither refused nor absent", async () => {
		const outage = new Error("connection reset");
		const record = Object.defineProperty({ ...validRecord() }, "clientName", {
			get() {
				throw outage;
			},
		});
		const boundary = validatedClientRepository(repositoryAnswering(record));
		await expect(boundary.lookupClient(CLIENT_ID)).rejects.toBe(outage);
	});

	it("asks the repository once per lookup, and reads each field once", async () => {
		const reads = new Map<string, number>();
		const inner = repositoryAnswering(ormEntity(validRecord(), reads));
		const findById = vi.spyOn(inner, "findById");
		const boundary = validatedClientRepository(inner);
		await boundary.lookupClient(CLIENT_ID);
		expect(findById).toHaveBeenCalledTimes(1);
		expect(Object.fromEntries(reads)).toEqual(
			Object.fromEntries(RECORD_FIELDS.map((field) => [field, 1])),
		);
	});

	it("is the same answer through a boundary handed to it again", async () => {
		const once = validatedClientRepository(repositoryAnswering(null));
		expect(validatedClientRepository(once)).toBe(once);
		expect(await validatedClientRepository(once).lookupClient(CLIENT_ID)).toEqual({
			outcome: "absent",
		});
	});
});

describe("validatedClientRepository — one boundary", () => {
	it("hands the repository the arguments it was given, on the repository itself", async () => {
		const seen: unknown[] = [];
		const inner = {
			record: validRecord(),
			async findById(this: { record: unknown }, clientId: string) {
				seen.push(["find", clientId]);
				return this.record as PublicClient;
			},
			async authenticate(this: { record: unknown }, clientId: string, secret: string) {
				seen.push(["authenticate", clientId, secret]);
				return this.record as PublicClient;
			},
		};
		const boundary = validatedClientRepository(inner);
		expect(await boundary.findById(CLIENT_ID)).not.toBeNull();
		expect(await boundary.authenticate(CLIENT_ID, "pw")).not.toBeNull();
		expect(seen).toEqual([
			["find", CLIENT_ID],
			["authenticate", CLIENT_ID, "pw"],
		]);
	});

	it("is not wrapped twice: a boundary handed to it is answered as it is", async () => {
		const reads = new Map<string, number>();
		const once = validatedClientRepository(repositoryAnswering(ormEntity(validRecord(), reads)));
		const twice = validatedClientRepository(once);
		expect(twice).toBe(once);
		await twice.findById(CLIENT_ID);
		expect(reads.get("clientId")).toBe(1);
	});

	it("disposes the repository it holds when the repository is disposable", async () => {
		const dispose = vi.fn(async () => {});
		const inner = { ...repositoryAnswering(null), [Symbol.asyncDispose]: dispose };
		const boundary = validatedClientRepository(inner) as unknown as AsyncDisposable;
		await boundary[Symbol.asyncDispose]();
		expect(dispose).toHaveBeenCalledTimes(1);
		expect(dispose.mock.contexts[0]).toBe(inner);
	});

	it("is not disposable when the repository it holds is not", () => {
		const boundary = validatedClientRepository(repositoryAnswering(null));
		expect(Symbol.asyncDispose in boundary).toBe(false);
	});
});
