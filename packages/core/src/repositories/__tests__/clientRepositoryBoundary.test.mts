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
 * registration schema. A record that fails makes the lookup reject with the
 * branded refusal (`isClientRecordRefused`), with one warn naming the client
 * id and the reasons. A field whose read throws is refused as unreadable,
 * never its value or what was thrown; the repository's own throw is the
 * store's outage. A logger that throws changes nothing of the answer, and
 * the boundary itself is frozen. A layer that lets rejections through keeps
 * the refusal.
 */

import { inspect } from "node:util";
import { describe, expect, it, vi } from "vitest";
import type { ClientRepository, PublicClient } from "#/repositories/ClientRepository.mjs";
import { isClientRecordRefused } from "#/repositories/clientRecordRefused.mjs";
import { validatedClientRepository } from "#/repositories/clientRepositoryBoundary.mjs";
import { logClientRepositoryUnavailable } from "#/repositories/clientRepositoryUnavailable.mjs";
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
 * Everything `value` holds, Errors expanded (name, message, stack, cause),
 * for a leak assertion: `JSON.stringify` renders an Error as `{}`.
 */
const rendered = (value: unknown): string => inspect(value, { depth: null });

/** What `answer` rejects with; fails when it resolves. */
const rejectionOf = async (answer: Promise<unknown>): Promise<unknown> => {
	try {
		await answer;
	} catch (error) {
		return error;
	}
	throw new Error("expected the lookup to reject");
};

/** Whether `answer` rejects with the branded refusal. */
const refusedBy = async (answer: Promise<unknown>): Promise<boolean> =>
	isClientRecordRefused(await rejectionOf(answer));

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
		expect(await boundary.findById(CLIENT_ID)).toMatchObject({
			clientId: CLIENT_ID,
			tokenEndpointAuthMethod: "private_key_jwt",
		});
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

describe("validatedClientRepository — a malformed record makes the lookup reject with the refusal", () => {
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
			"a front-channel logout URI whose query carries sid",
			{ frontchannelLogoutUri: "https://rp.example/frontchannel?sid=1" },
			"frontchannelLogoutUri",
		],
		[
			"a front-channel logout URI whose query carries iss in another case",
			{ frontchannelLogoutUri: "https://rp.example/frontchannel?ISS=1" },
			"frontchannelLogoutUri",
		],
		[
			"a front-channel logout URI whose query name is percent-encoded",
			{ frontchannelLogoutUri: "https://rp.example/frontchannel?%73id=1" },
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
			expect(await refusedBy(boundary.findById(CLIENT_ID))).toBe(true);
			expect(await refusedBy(boundary.authenticate(CLIENT_ID, "secret"))).toBe(true);
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

	it("names the parameter a refused front-channel logout URI carries, never the URI", async () => {
		const logger = recordingLogger();
		const boundary = validatedClientRepository(
			repositoryAnswering({
				...validRecord(),
				frontchannelLogoutUri: "https://rp.example/frontchannel?sid=leak",
			}),
			{ logger },
		);
		expect(await refusedBy(boundary.findById(CLIENT_ID))).toBe(true);
		const [[line]] = logger.warn.mock.calls as [[Record<string, unknown>, string]];
		const reasons = line.reasons as string[];
		expect(
			reasons.some((reason) => /^frontchannelLogoutUri: .*already carries .sid./.test(reason)),
			reasons.join("; "),
		).toBe(true);
		expect(reasons.join("; ")).not.toContain("leak");
	});

	it("refuses an answer that is not an object", async () => {
		for (const answer of ["client-1", 42, true, [validRecord()]]) {
			const logger = recordingLogger();
			const boundary = validatedClientRepository(repositoryAnswering(answer), { logger });
			expect(await refusedBy(boundary.findById(CLIENT_ID))).toBe(true);
			expect(logger.warn).toHaveBeenCalledWith(
				{ step: "find", clientId: CLIENT_ID, reasons: ["not an object"] },
				"client_record_refused",
			);
		}
	});

	it("refuses a record whose shape cannot be read, as not an object", async () => {
		// Revoked once `await` has read its `then`: what reaches the boundary
		// is a Proxy every read of which throws.
		const revokedOnArrival = () => {
			const { proxy, revoke } = Proxy.revocable(validRecord(), {
				get(target, key, receiver) {
					if (key === "then") {
						revoke();
						return undefined;
					}
					return Reflect.get(target, key, receiver);
				},
			});
			return proxy;
		};
		const logger = recordingLogger();
		const boundary = validatedClientRepository(
			{
				findById: async () => revokedOnArrival() as PublicClient,
				authenticate: async () => revokedOnArrival() as PublicClient,
			},
			{ logger },
		);
		expect(await refusedBy(boundary.findById(CLIENT_ID))).toBe(true);
		expect(await refusedBy(boundary.authenticate(CLIENT_ID, "secret"))).toBe(true);
		expect(logger.warn.mock.calls.map(([line]) => line)).toEqual([
			{ step: "find", clientId: CLIENT_ID, reasons: ["not an object"] },
			{ step: "authenticate", clientId: CLIENT_ID, reasons: ["not an object"] },
		]);
	});

	it("logs the client id and the reasons, never the record", async () => {
		const logger = recordingLogger();
		const record = { ...validRecord(), clientSecret: "do-not-log-me", firstParty: "true" };
		const boundary = validatedClientRepository(repositoryAnswering(record), { logger });
		await rejectionOf(boundary.findById(CLIENT_ID));
		const line = rendered(logger.warn.mock.calls);
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
			expect(await refusedBy(boundary.findById(clientId)), JSON.stringify(clientId)).toBe(true);
			const [[line]] = logger.warn.mock.calls as [[Record<string, unknown>, string]];
			const reasons = line.reasons as string[];
			expect(
				reasons.some((r) => r.startsWith("clientId:")),
				reasons.join("; "),
			).toBe(true);
		}
		const longest = validatedClientRepository(
			repositoryAnswering({ ...validRecord(), clientId: "x".repeat(256) }),
		);
		expect(await longest.findById("x".repeat(256))).toMatchObject({ clientId: "x".repeat(256) });
	});

	it("sanitises the client id it logs, the client's own input", async () => {
		const logger = recordingLogger();
		const refusing = validatedClientRepository(
			repositoryAnswering({ ...validRecord(), clientId: "a\nb" }),
			{ logger },
		);
		expect(await refusedBy(refusing.findById("a\nb"))).toBe(true);
		expect(logger.warn.mock.calls[0]?.[0]).toMatchObject({ clientId: "a?b" });
	});

	it("names a refused URI by its field and position, never by the URI, in the reasons and the warn", async () => {
		const SECRET = "tok-3f9a";
		const logger = recordingLogger();
		const boundary = validatedClientRepository(
			repositoryAnswering({
				...validRecord(),
				allowedRedirectUris: [
					"https://rp.example/cb",
					`https://rp.example/cb?token=${SECRET}&iss=x`,
				],
				federationGrantRedirectUris: [`https://rp.example/grant?token=${SECRET}&grant_id=1`],
			}),
			{ logger },
		);
		expect(await refusedBy(boundary.findById(CLIENT_ID))).toBe(true);
		const [[line]] = logger.warn.mock.calls as [[Record<string, unknown>, string]];
		const reasons = (line.reasons as string[]).join("\n");
		expect(reasons).toContain("allowedRedirectUris[1]: ");
		expect(reasons).toContain("federationGrantRedirectUris[0]: ");
		expect(reasons).not.toContain(SECRET);
		expect(rendered(logger.warn.mock.calls)).not.toContain(SECRET);
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
		expect(await refusedBy(boundary.findById(CLIENT_ID))).toBe(true);
		const [line] = logger.warn.mock.calls[0] as [Record<string, unknown>];
		expect(line.reasons).toHaveLength(10);
		expect(line.reasonCount).toBe(12);
	});

	it("refuses a function answered as the record", async () => {
		const logger = recordingLogger();
		const record = Object.assign(() => {}, validRecord());
		const boundary = validatedClientRepository(repositoryAnswering(record), { logger });
		expect(await refusedBy(boundary.findById(CLIENT_ID))).toBe(true);
		expect(await refusedBy(boundary.authenticate(CLIENT_ID, "secret"))).toBe(true);
		expect(logger.warn.mock.calls.map(([line]) => line)).toEqual([
			{ step: "find", clientId: CLIENT_ID, reasons: ["not an object"] },
			{ step: "authenticate", clientId: CLIENT_ID, reasons: ["not an object"] },
		]);
	});

	it("rejects with a refusal that carries nothing of the record or its reasons", async () => {
		const SECRET = "tok-3f9a";
		const boundary = validatedClientRepository(
			repositoryAnswering({
				...validRecord(),
				clientName: "",
				allowedRedirectUris: [`https://rp.example/cb?token=${SECRET}&iss=x`],
			}),
			{ logger: recordingLogger() },
		);
		const refusal = await rejectionOf(boundary.findById(CLIENT_ID));
		expect(isClientRecordRefused(refusal)).toBe(true);
		expect(Object.isFrozen(refusal)).toBe(true);
		const carried = rendered(refusal);
		expect(carried).not.toContain(SECRET);
		expect(carried).not.toContain(CLIENT_ID);
		expect(carried).not.toContain("allowedRedirectUris");
	});

	it("rejects with a new refusal for each lookup", async () => {
		const boundary = validatedClientRepository(
			repositoryAnswering({ ...validRecord(), firstParty: "true" }),
			{ logger: recordingLogger() },
		);
		const first = await rejectionOf(boundary.findById(CLIENT_ID));
		const second = await rejectionOf(boundary.findById(CLIENT_ID));
		expect(isClientRecordRefused(first) && isClientRecordRefused(second)).toBe(true);
		expect(first).not.toBe(second);
	});

	it("answers a refused record with the refusal when its logger throws, and a valid one as it is", async () => {
		const SAID = "logger sink down: tok-3f9a";
		const logger = {
			warn: vi.fn(() => {
				throw new Error(SAID);
			}),
		};
		const refusing = validatedClientRepository(
			repositoryAnswering({ ...validRecord(), firstParty: "true" }),
			{ logger },
		);
		const found = await rejectionOf(refusing.findById(CLIENT_ID));
		const authenticated = await rejectionOf(refusing.authenticate(CLIENT_ID, "secret"));
		expect(isClientRecordRefused(found) && isClientRecordRefused(authenticated)).toBe(true);
		expect(logger.warn).toHaveBeenCalledTimes(2);
		const outage = { error: vi.fn() };
		logClientRepositoryUnavailable(outage, { step: "find", clientId: CLIENT_ID }, found);
		expect(rendered(outage.error.mock.calls)).not.toContain("tok-3f9a");
		const valid = validatedClientRepository(repositoryAnswering(validRecord()), { logger });
		expect(await valid.findById(CLIENT_ID)).toEqual(validRecord());
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

describe("validatedClientRepository — a field whose read throws is refused as unreadable", () => {
	/** What a throw may carry: the field's value, quoted by a driver's message. */
	const VALUE = "https://rp.example/cb?token=tok-3f9a";

	/** `validRecord()` whose `field` is read through `read`, which throws. */
	const unreadableAt = (field: string, read: () => unknown): object =>
		Object.defineProperty({ ...validRecord() }, field, { get: read, enumerable: true });

	const CASES: ReadonlyArray<readonly [string, object, string]> = [
		[
			"a getter throwing an Error that quotes the value",
			unreadableAt("allowedRedirectUris", () => {
				throw new Error(`column allowedRedirectUris failed to load: ${VALUE}`);
			}),
			"allowedRedirectUris: unreadable",
		],
		[
			"a getter throwing a string",
			unreadableAt("clientName", () => {
				throw `lazy load of ${VALUE}`;
			}),
			"clientName: unreadable",
		],
		[
			"a nested object's getter",
			{
				...validRecord(),
				senderConstrained: Object.defineProperty({ required: true }, "methods", {
					get() {
						throw new TypeError(`cannot read ${VALUE}`);
					},
					enumerable: true,
				}),
			},
			"senderConstrained: unreadable",
		],
		[
			"a Proxy-backed list whose element read throws",
			{
				...validRecord(),
				allowedScopes: new Proxy(["openid"], {
					get(target, key, receiver) {
						if (key === "0") throw new RangeError(VALUE);
						return Reflect.get(target, key, receiver);
					},
				}),
			},
			"allowedScopes: unreadable",
		],
	];

	for (const [name, record, reason] of CASES) {
		it(`refuses ${name}, naming the field, never the value or what was thrown`, async () => {
			const logger = recordingLogger();
			const boundary = validatedClientRepository(repositoryAnswering(record), { logger });
			const found = await rejectionOf(boundary.findById(CLIENT_ID));
			const authenticated = await rejectionOf(boundary.authenticate(CLIENT_ID, "secret"));
			expect(isClientRecordRefused(found) && isClientRecordRefused(authenticated)).toBe(true);
			expect(logger.warn.mock.calls).toEqual([
				[{ step: "find", clientId: CLIENT_ID, reasons: [reason] }, "client_record_refused"],
				[{ step: "authenticate", clientId: CLIENT_ID, reasons: [reason] }, "client_record_refused"],
			]);
			// Neither the warn, the refusal, nor the outage line a caller writes
			// for it carries the value or the thrown message.
			const outage = { error: vi.fn() };
			logClientRepositoryUnavailable(outage, { step: "find", clientId: CLIENT_ID }, found);
			expect(outage.error.mock.calls[0]?.[0]).toMatchObject({
				err: { reason: "client_record_refused" },
			});
			const said = rendered([logger.warn.mock.calls, outage.error.mock.calls, found]);
			expect(said).not.toContain("tok-3f9a");
			expect(said).not.toContain("failed to load");
			expect(said).not.toContain("lazy load");
			expect(said).not.toContain("cannot read");
		});
	}

	it("still lets the repository's own throw through, as the store's outage", async () => {
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

describe("validatedClientRepository — the refusal survives a layer that lets rejections through", () => {
	const refusingBoundary = (logger = recordingLogger()) =>
		validatedClientRepository(repositoryAnswering({ ...validRecord(), firstParty: "true" }), {
			logger,
		});

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

	const LAYERS: ReadonlyArray<readonly [string, (inner: ClientRepository) => ClientRepository]> = [
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
		it(`rejects with the same refusal through ${name}`, async () => {
			const boundary = refusingBoundary();
			const layered = layer(boundary);
			const refusal = await rejectionOf(layered.findById(CLIENT_ID));
			expect(isClientRecordRefused(refusal)).toBe(true);
			expect(await refusedBy(layered.authenticate(CLIENT_ID, "secret"))).toBe(true);
		});

		it(`is refused by a boundary over ${name} over a boundary, warned once by the inner one`, async () => {
			const innerLogger = recordingLogger();
			const outerLogger = recordingLogger();
			const outer = validatedClientRepository(layer(refusingBoundary(innerLogger)), {
				logger: outerLogger,
			});
			expect(await refusedBy(outer.findById(CLIENT_ID))).toBe(true);
			expect(innerLogger.warn).toHaveBeenCalledTimes(1);
			expect(outerLogger.warn).not.toHaveBeenCalled();
		});

		it(`lets the refusal through a boundary over ${name} on both lookups, never answering null`, async () => {
			const outer = validatedClientRepository(layer(refusingBoundary()), {
				logger: recordingLogger(),
			});
			expect(await refusedBy(outer.findById(CLIENT_ID))).toBe(true);
			expect(await refusedBy(outer.authenticate(CLIENT_ID, "secret"))).toBe(true);
		});
	}

	it("answers a valid record through a boundary over a forwarder over a boundary", async () => {
		const inner = validatedClientRepository(repositoryAnswering(validRecord()));
		const outer = validatedClientRepository({ ...inner });
		expect(await outer.findById(CLIENT_ID)).toEqual(await inner.findById(CLIENT_ID));
	});

	it("still lets an outage through a layer as an outage, never as a refusal", async () => {
		const outage = new Error("store down");
		const boundary = validatedClientRepository({
			findById: async () => {
				throw outage;
			},
			authenticate: async () => {
				throw outage;
			},
		});
		const outer = validatedClientRepository({ ...boundary });
		const rejection = await rejectionOf(outer.findById(CLIENT_ID));
		expect(rejection).toBe(outage);
		expect(isClientRecordRefused(rejection)).toBe(false);
	});
});

describe("validatedClientRepository — what it answers is frozen", () => {
	it("freezes the answer at every depth, the schema's defaults included", async () => {
		const boundary = validatedClientRepository(repositoryAnswering(validRecord()));
		const found = await boundary.findById(CLIENT_ID);
		const authenticated = await boundary.authenticate(CLIENT_ID, "secret");
		expect(found).not.toBeNull();
		expect(authenticated).not.toBeNull();
		const unfrozen: string[] = [];
		const walk = (value: unknown, at: string): void => {
			if (typeof value !== "object" || value === null) return;
			if (!Object.isFrozen(value)) unfrozen.push(at);
			for (const [key, inner] of Object.entries(value)) walk(inner, `${at}.${key}`);
		};
		walk(found, "findById");
		walk(authenticated, "authenticate");
		expect(unfrozen).toEqual([]);
		const defaulted = await validatedClientRepository(
			repositoryAnswering({ clientId: CLIENT_ID, tokenEndpointAuthMethod: "none" }),
		).findById(CLIENT_ID);
		expect(Object.isFrozen(defaulted?.allowedRedirectUris)).toBe(true);
		expect(Object.isFrozen(defaulted?.allowedAudiences)).toBe(true);
	});

	it("freezes nested objects: the key set and the sender constraint", async () => {
		const boundary = validatedClientRepository(
			repositoryAnswering({
				...validRecord(),
				tokenEndpointAuthMethod: "private_key_jwt",
				jwks: {
					keys: [{ kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" }],
				},
			}),
		);
		const client = await boundary.findById(CLIENT_ID);
		expect(Object.isFrozen(client?.jwks)).toBe(true);
		expect(Object.isFrozen(client?.jwks?.keys)).toBe(true);
		expect(Object.isFrozen(client?.jwks?.keys[0])).toBe(true);
		expect(Object.isFrozen(client?.senderConstrained)).toBe(true);
		expect(Object.isFrozen(client?.senderConstrained?.methods)).toBe(true);
	});
});

describe("validatedClientRepository — found, refused and absent, through the port", () => {
	it("answers a valid record as its validated, frozen copy, a fresh one per lookup", async () => {
		const boundary = validatedClientRepository(repositoryAnswering(validRecord()));
		const first = await boundary.findById(CLIENT_ID);
		const second = await boundary.findById(CLIENT_ID);
		expect(first).toEqual(validRecord());
		expect(Object.isFrozen(first)).toBe(true);
		expect(second).toEqual(first);
		expect(second).not.toBe(first);
		expect(second?.allowedScopes).not.toBe(first?.allowedScopes);
	});

	it("rejects with the refusal for a record it refuses, and warns once with the reasons", async () => {
		const logger = recordingLogger();
		const boundary = validatedClientRepository(
			repositoryAnswering({ ...validRecord(), firstParty: "true" }),
			{ logger },
		);
		expect(await refusedBy(boundary.findById(CLIENT_ID))).toBe(true);
		expect(logger.warn).toHaveBeenCalledTimes(1);
		const [[line, message]] = logger.warn.mock.calls as [[Record<string, unknown>, string]];
		expect(message).toBe("client_record_refused");
		expect(line).toMatchObject({ step: "find", clientId: CLIENT_ID });
		const reasons = line.reasons as string[];
		expect(
			reasons.some((r) => r.startsWith("firstParty:")),
			reasons.join("; "),
		).toBe(true);
	});

	it("refuses a record under another id, never answering null", async () => {
		const logger = recordingLogger();
		const boundary = validatedClientRepository(
			repositoryAnswering({ ...validRecord(), clientId: "CLIENT-1" }),
			{ logger },
		);
		expect(await refusedBy(boundary.findById(CLIENT_ID))).toBe(true);
		expect(await refusedBy(boundary.authenticate(CLIENT_ID, "secret"))).toBe(true);
		expect(logger.warn.mock.calls.map(([line]) => line.reasons)).toEqual([
			["clientId: not the id that was looked up"],
			["clientId: not the id that was looked up"],
		]);
	});

	it("asks the repository once per lookup, and reads each field once", async () => {
		const reads = new Map<string, number>();
		const inner = repositoryAnswering(ormEntity(validRecord(), reads));
		const findById = vi.spyOn(inner, "findById");
		const boundary = validatedClientRepository(inner);
		await boundary.findById(CLIENT_ID);
		expect(findById).toHaveBeenCalledTimes(1);
		expect(Object.fromEntries(reads)).toEqual(
			Object.fromEntries(RECORD_FIELDS.map((field) => [field, 1])),
		);
		const authenticate = vi.spyOn(inner, "authenticate");
		await boundary.authenticate(CLIENT_ID, "secret");
		expect(authenticate).toHaveBeenCalledTimes(1);
		expect(findById).toHaveBeenCalledTimes(1);
	});

	it("answers the same through a boundary handed to it again: null, or the refusal warned once", async () => {
		const absent = validatedClientRepository(repositoryAnswering(null));
		expect(validatedClientRepository(absent)).toBe(absent);
		expect(await validatedClientRepository(absent).findById(CLIENT_ID)).toBeNull();
		const logger = recordingLogger();
		const refusing = validatedClientRepository(
			repositoryAnswering({ ...validRecord(), firstParty: "true" }),
			{ logger },
		);
		const again = validatedClientRepository(refusing, { logger: recordingLogger() });
		expect(await refusedBy(again.findById(CLIENT_ID))).toBe(true);
		expect(logger.warn).toHaveBeenCalledTimes(1);
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

	it("is frozen: no consumer can replace its lookups or its dispose", async () => {
		const boundary = validatedClientRepository(repositoryAnswering(validRecord()));
		expect(Object.isFrozen(boundary)).toBe(true);
		const replacement = async () => null;
		expect(() => {
			(boundary as { findById: unknown }).findById = replacement;
		}).toThrow(TypeError);
		expect(() => {
			(boundary as { authenticate: unknown }).authenticate = replacement;
		}).toThrow(TypeError);
		expect(() => {
			(boundary as { [Symbol.asyncDispose]?: unknown })[Symbol.asyncDispose] = replacement;
		}).toThrow(TypeError);
		expect(() => Object.defineProperty(boundary, "findById", { value: replacement })).toThrow(
			TypeError,
		);
		expect(validatedClientRepository(boundary)).toBe(boundary);
		expect(await boundary.findById(CLIENT_ID)).toEqual(validRecord());
	});

	it("disposes the repository it holds when the repository is disposable", async () => {
		const dispose = vi.fn(async () => {});
		const inner = { ...repositoryAnswering(null), [Symbol.asyncDispose]: dispose };
		const boundary = validatedClientRepository(inner) as unknown as AsyncDisposable;
		await boundary[Symbol.asyncDispose]();
		expect(dispose).toHaveBeenCalledTimes(1);
		expect(dispose.mock.contexts[0]).toBe(inner);
	});

	it("disposes nothing when the repository it holds is not disposable", async () => {
		const boundary = validatedClientRepository(
			repositoryAnswering(null),
		) as unknown as AsyncDisposable;
		await expect(boundary[Symbol.asyncDispose]()).resolves.toBeUndefined();
	});

	it("reads nothing of the repository it holds when it is built", () => {
		const reads: (string | symbol)[] = [];
		const throwing = new Proxy(
			{},
			{
				get(_target, key) {
					reads.push(key);
					throw new Error("a read the boundary must not make");
				},
			},
		) as ClientRepository;
		expect(() => validatedClientRepository(throwing)).not.toThrow();
		expect(reads).toEqual([]);
	});

	it("reads the repository's dispose only when it is disposed", async () => {
		const dispose = vi.fn(async () => {});
		let reads = 0;
		const inner = {
			...repositoryAnswering(null),
			get [Symbol.asyncDispose]() {
				reads += 1;
				return dispose;
			},
		};
		const boundary = validatedClientRepository(inner) as unknown as AsyncDisposable;
		expect(reads).toBe(0);
		await boundary[Symbol.asyncDispose]();
		expect(reads).toBe(1);
		expect(dispose).toHaveBeenCalledTimes(1);
		expect(dispose.mock.contexts[0]).toBe(inner);
	});
});

describe("validatedClientRepository — it answers through the port alone", () => {
	// The names are type-only, so a runtime `name in mod` check would pass
	// whether or not the entry exports them. vitest's typecheck mode checks
	// this file, so each `@ts-expect-error` fails the run once the name is
	// exported again.
	it("exports no verdict type and no repository type beside ClientRepository", () => {
		if (false as boolean) {
			// @ts-expect-error — the boundary answers no verdict
			type _Lookup = import("#/index.mjs").ClientLookup;
			// @ts-expect-error — the boundary is a ClientRepository, with no type of its own
			type _Validated = import("#/index.mjs").ValidatedClientRepository;
		}
		expect(true).toBe(true);
	});

	it("carries the port's two lookups and its dispose, and nothing else", () => {
		expect(Reflect.ownKeys(validatedClientRepository(repositoryAnswering(null)))).toEqual([
			"findById",
			"authenticate",
			Symbol.asyncDispose,
		]);
	});
});
