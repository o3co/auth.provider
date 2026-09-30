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
 * `HttpMfaFactorStore` against a Store that breaks the contract, over the
 * test kit's fake Store and over bare `node:http` servers where a test needs
 * what the fake does not give (a status text, a request line). Every answer
 * outside the contract throws — never "no factors", never a success — and
 * what it throws carries nothing the Store sent. The adapter sends the
 * sealed `data` it is handed, byte for byte, and nothing it was sealed from.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { inspect } from "node:util";
import {
	auditedError,
	loggableError,
	type MfaFactorRecord,
	sealWithKeyRing,
	toMfaStoreFactor,
} from "@o3co/auth-provider-core";
import { type FakeStore, startFakeStore } from "@o3co/auth-provider-test-kit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	HttpMfaFactorStore,
	MfaStoreError,
	StoreCredentialRefusedError,
	StoreTransportError,
} from "#/index.mjs";

const TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ID = "u1PIlRkb_cy7UmjYUKaL_A";
const OTHER_ID = "v2QJmSlc-dz8VnkZVLbM_B";

/** Text the Store wrote, which must reach nothing an error carries. */
const MARKER = "STORE-WROTE-THIS";

const RECORD: MfaFactorRecord = {
	id: ID,
	subject: "user-1",
	kind: "totp",
	label: "Phone",
	binding: "password",
	createdAt: new Date("2026-09-01T00:00:00.000Z"),
	lastUsedAt: new Date("2026-09-02T00:00:00.000Z"),
	version: 1,
	data: "v2.opaque-sealed-data",
};
const WIRE = toMfaStoreFactor(RECORD);
const NEXT = {
	data: "v2.re-sealed",
	label: "Work phone",
	lastUsedAt: new Date("2026-09-03T00:00:00.000Z"),
};

let fake: FakeStore;
beforeEach(async () => {
	fake = await startFakeStore({ bearerToken: TOKEN });
});
afterEach(async () => {
	await fake.close();
});

const urlsOf = (from: FakeStore) => ({
	listUrl: from.urls.listUrl,
	createUrl: from.urls.createUrl,
	updateUrl: from.urls.updateUrl,
	deleteUrl: from.urls.deleteUrl,
});

/** The adapter over the fake Store, with `overrides` laid over its options. */
const storeOver = (
	overrides: Partial<ConstructorParameters<typeof HttpMfaFactorStore>[0]> = {},
): HttpMfaFactorStore =>
	new HttpMfaFactorStore({
		...urlsOf(fake),
		bearerToken: TOKEN,
		timeout: 5000,
		...overrides,
	});

const json = (status: number, value: unknown) => ({
	status,
	headers: { "Content-Type": "application/json" },
	body: typeof value === "string" ? value : JSON.stringify(value),
});

/** The error `promise` rejects with. */
async function rejection(promise: Promise<unknown>): Promise<Error> {
	try {
		await promise;
	} catch (error) {
		return error as Error;
	}
	throw new Error("expected a rejection");
}

/** Every form in which an error leaves the adapter: its message, its fields, how it prints, and its projections. */
const everyForm = (error: Error): string =>
	[
		error.message,
		JSON.stringify(error),
		JSON.stringify(
			Object.getOwnPropertyNames(error).map((key) => [key, String((error as never)[key])]),
		),
		inspect(error, { depth: 5 }),
		JSON.stringify(loggableError(error)),
		JSON.stringify(auditedError(error)),
	].join("\n");

let servers: Server[] = [];
afterEach(async () => {
	await Promise.all(
		servers.map((server) => {
			server.closeAllConnections();
			return new Promise<void>((resolve) => server.close(() => resolve()));
		}),
	);
	servers = [];
});

/** Starts a bare server on its own loopback port and returns its origin. */
async function serve(
	handler: (request: IncomingMessage, body: string, response: ServerResponse) => void,
): Promise<string> {
	const server = createServer((request, response) => {
		const chunks: Buffer[] = [];
		request.on("data", (chunk: Buffer) => chunks.push(chunk));
		request.on("end", () => handler(request, Buffer.concat(chunks).toString("utf8"), response));
	});
	servers.push(server);
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as { port: number };
	return `http://127.0.0.1:${port}`;
}

/** The adapter over a bare server at `origin`, each endpoint at its own path. */
const storeAt = (origin: string, bearerToken?: string): HttpMfaFactorStore =>
	new HttpMfaFactorStore({
		listUrl: `${origin}/mfa/list?tenant=a`,
		createUrl: `${origin}/mfa/create`,
		updateUrl: `${origin}/mfa/update`,
		deleteUrl: `${origin}/mfa/delete`,
		...(bearerToken === undefined ? {} : { bearerToken }),
		timeout: 5000,
	});

describe("what it sends", () => {
	it("posts JSON to each URL as configured, with the bearer token, and no subject or factor id in the request line", async () => {
		const seen: {
			method?: string;
			url?: string;
			headers: IncomingMessage["headers"];
			body: unknown;
		}[] = [];
		const origin = await serve((request, body, response) => {
			seen.push({
				method: request.method,
				url: request.url,
				headers: request.headers,
				body: JSON.parse(body),
			});
			if (request.url?.startsWith("/mfa/list")) {
				response.writeHead(200, { "Content-Type": "application/json" });
				response.end(JSON.stringify({ factors: [] }));
			} else if (request.url === "/mfa/update") {
				response.writeHead(404).end();
			} else {
				response.writeHead(204).end();
			}
		});
		const store = storeAt(origin, TOKEN);
		await store.list("user-1");
		await store.create(RECORD);
		await store.update("user-1", ID, 1, NEXT);
		await store.remove("user-1", ID);
		await store.removeAllForSubject("user-1");
		expect(seen.map(({ method, url }) => [method, url])).toEqual([
			["POST", "/mfa/list?tenant=a"],
			["POST", "/mfa/create"],
			["POST", "/mfa/update"],
			["POST", "/mfa/delete"],
			["POST", "/mfa/delete"],
		]);
		for (const request of seen) {
			expect(request.headers["content-type"]).toBe("application/json");
			expect(request.headers.authorization).toBe(`Bearer ${TOKEN}`);
		}
		expect(seen.map((request) => request.body)).toEqual([
			{ subject: "user-1" },
			{ factor: WIRE },
			{
				subject: "user-1",
				id: ID,
				expectedVersion: 1,
				changes: { data: NEXT.data, label: NEXT.label, lastUsedAtMs: NEXT.lastUsedAt.getTime() },
			},
			{ subject: "user-1", id: ID },
			{ subject: "user-1", all: true },
		]);
	});

	it("sends no Authorization header without a bearer token", async () => {
		const authorizations: (string | undefined)[] = [];
		const origin = await serve((request, _body, response) => {
			authorizations.push(request.headers.authorization);
			response.writeHead(200, { "Content-Type": "application/json" });
			response.end(JSON.stringify({ factors: [] }));
		});
		await storeAt(origin).list("user-1");
		expect(authorizations).toEqual([undefined]);
	});

	it("sends the sealed data it is handed byte for byte, and nothing it was sealed from", async () => {
		const ring = [{ id: "k1", key: Buffer.alloc(32, 7) }];
		const seal = (plaintext: string) =>
			sealWithKeyRing(plaintext, ring, { purpose: "o3co:mfa:factor", record: Buffer.from(ID) });
		const created = seal('{"secret":"PLAINTEXT-SECRET-ONE"}');
		const resealed = seal('{"secret":"PLAINTEXT-SECRET-TWO"}');
		const store = storeOver();
		await store.create({ ...RECORD, data: created });
		await store.update("user-1", ID, 1, { ...NEXT, data: resealed });
		expect(fake.requests.map((request) => request.body)).toMatchObject([
			{ factor: { data: created } },
			{ changes: { data: resealed } },
		]);
		expect(JSON.stringify(fake.requests)).not.toContain("PLAINTEXT-SECRET");
		expect(fake.factors("user-1")).toEqual([
			{
				...WIRE,
				data: resealed,
				label: NEXT.label,
				lastUsedAtMs: NEXT.lastUsedAt.getTime(),
				version: 2,
			},
		]);
	});

	it("refuses, with a RangeError and sending nothing, a record or an update the wire cannot carry", async () => {
		const store = storeOver();
		await expect(store.create({ ...RECORD, id: "factor-1" })).rejects.toThrow(RangeError);
		await expect(store.create({ ...RECORD, label: "" })).rejects.toThrow(RangeError);
		await expect(store.create({ ...RECORD, createdAt: new Date(Number.NaN) })).rejects.toThrow(
			RangeError,
		);
		await expect(store.update("user-1", "factor-1", 1, NEXT)).rejects.toThrow(RangeError);
		await expect(store.update("user-1", ID, Number.MAX_SAFE_INTEGER, NEXT)).rejects.toThrow(
			RangeError,
		);
		await expect(store.update("user-1", ID, 1.5, NEXT)).rejects.toThrow(RangeError);
		expect(fake.requests).toEqual([]);
	});
});

describe("list", () => {
	it("answers the subject's records as the port's records", async () => {
		const bare = toMfaStoreFactor({
			...RECORD,
			id: OTHER_ID,
			label: undefined,
			binding: undefined,
			lastUsedAt: undefined,
		});
		fake.holdFactor("user-1", WIRE);
		fake.holdFactor("user-1", bare);
		expect(await storeOver().list("user-1")).toStrictEqual([
			RECORD,
			{ ...RECORD, id: OTHER_ID, label: undefined, binding: undefined, lastUsedAt: undefined },
		]);
		expect(await storeOver().list("user-2")).toStrictEqual([]);
	});

	it("throws on a 404, a 5xx, a redirect or any other status — never answering no factors — and follows no redirect", async () => {
		for (const status of [404, 500, 502, 503, 301, 302, 303, 307, 308, 201, 204, 400]) {
			fake.answer("list", () => ({
				status,
				headers: { Location: fake.urls.listUrl },
				body: status === 204 ? undefined : JSON.stringify({ factors: [] }),
			}));
			const before = fake.requests.length;
			const error = await rejection(storeOver().list("user-1"));
			expect(error, String(status)).toBeInstanceOf(MfaStoreError);
			expect((error as MfaStoreError).reason, String(status)).toBe("unexpected_status");
			expect((error as MfaStoreError).operation).toBe("list");
			expect((error as MfaStoreError).storeStatus).toBe(status);
			expect(fake.requests.length - before, String(status)).toBe(1);
		}
	});

	it("throws on a 200 whose body is not { factors: [...] }", async () => {
		for (const body of ["not json", "{}", '{"factors":{}}', "null", "[]", '{"factors":null}']) {
			fake.answer("list", () => json(200, body));
			const error = await rejection(storeOver().list("user-1"));
			expect(error, body).toBeInstanceOf(MfaStoreError);
			expect((error as MfaStoreError).reason, body).toBe("malformed_answer");
		}
	});

	it("throws, never answering fewer records, on a record it cannot read", async () => {
		for (const [what, record] of [
			["an id out of shape", { ...WIRE, id: "factor-1" }],
			["a null label", { ...WIRE, label: null }],
			["a date as text", { ...WIRE, createdAtMs: "2026-09-01" }],
			["a fractional version", { ...WIRE, version: 1.5 }],
			["no data", { ...WIRE, data: undefined }],
			["a binding outside the three", { ...WIRE, binding: "admin" }],
			["not an object", "record"],
		] as const) {
			const held = await startFakeStore({ bearerToken: TOKEN });
			try {
				held.holdFactor("user-1", toMfaStoreFactor({ ...RECORD, id: OTHER_ID }));
				held.holdFactor("user-1", record);
				const error = await rejection(
					new HttpMfaFactorStore({ ...urlsOf(held), bearerToken: TOKEN, timeout: 5000 }).list(
						"user-1",
					),
				);
				expect(error, what).toBeInstanceOf(MfaStoreError);
				expect((error as MfaStoreError).reason, what).toBe("unreadable_record");
			} finally {
				await held.close();
			}
		}
	});

	it("throws on a record of another subject in the subject's list", async () => {
		fake.holdFactor("user-1", WIRE);
		fake.holdFactor("user-1", { ...WIRE, id: OTHER_ID, subject: "user-2" });
		const error = await rejection(storeOver().list("user-1"));
		expect((error as MfaStoreError).reason).toBe("unreadable_record");
	});

	it("throws on a list that names one id twice", async () => {
		fake.holdFactor("user-1", WIRE);
		fake.holdFactor("user-1", { ...WIRE, data: "v2.twin" });
		const error = await rejection(storeOver().list("user-1"));
		expect((error as MfaStoreError).reason).toBe("unreadable_record");
	});
});

describe("create", () => {
	it("answers a 409 with a throw, the duplicate refused", async () => {
		const store = storeOver();
		await store.create(RECORD);
		await expect(store.create({ ...RECORD, data: "v2.other" })).rejects.toThrow(/already exists/);
		expect(fake.factors("user-1")).toEqual([WIRE]);
	});

	it("takes any 2xx as created", async () => {
		for (const status of [200, 201, 202, 204]) {
			fake.answer("create", () => ({ status, body: status === 204 ? undefined : "{}" }));
			await expect(storeOver().create(RECORD), String(status)).resolves.toBeUndefined();
		}
	});

	it("throws on any other status, a redirect included", async () => {
		for (const status of [400, 404, 500, 503, 307, 302]) {
			fake.answer("create", () => ({ status, headers: { Location: fake.urls.createUrl } }));
			const error = await rejection(storeOver().create(RECORD));
			expect((error as MfaStoreError).reason, String(status)).toBe("unexpected_status");
			expect((error as MfaStoreError).operation).toBe("create");
		}
	});
});

describe("update", () => {
	it("answers a 409 or a 404 with null", async () => {
		for (const status of [409, 404]) {
			fake.answer("update", () => ({ status }));
			expect(await storeOver().update("user-1", ID, 1, NEXT), String(status)).toBeNull();
		}
	});

	it("throws on a version other than the expected one plus one, naming the subject and the factor id", async () => {
		for (const version of [1, 3, 0, 100]) {
			fake.answer("update", () =>
				json(200, {
					factor: {
						...WIRE,
						data: NEXT.data,
						label: NEXT.label,
						lastUsedAtMs: NEXT.lastUsedAt.getTime(),
						version,
					},
				}),
			);
			const error = await rejection(storeOver().update("user-1", ID, 1, NEXT));
			expect((error as MfaStoreError).reason, String(version)).toBe("version_skipped");
			expect(error.message.startsWith(`subject user-1, factor ${ID}: `)).toBe(true);
		}
	});

	it("throws on an answer naming another record, or one that did not write the changes", async () => {
		const written = {
			...WIRE,
			data: NEXT.data,
			label: NEXT.label,
			lastUsedAtMs: NEXT.lastUsedAt.getTime(),
			version: 2,
		};
		const { lastUsedAtMs: _dropped, ...unused } = written;
		for (const [what, factor] of [
			["another id", { ...written, id: OTHER_ID }],
			["another subject", { ...written, subject: "user-2" }],
			["other data", { ...written, data: "v2.not-what-was-sent" }],
			["another label", { ...written, label: "Other" }],
			["another lastUsedAtMs", { ...written, lastUsedAtMs: 1 }],
			["lastUsedAtMs left out", unused],
			["an unreadable record", { ...written, createdAtMs: "x" }],
		] as const) {
			fake.answer("update", () => json(200, { factor }));
			const error = await rejection(storeOver().update("user-1", ID, 1, NEXT));
			expect(error, what).toBeInstanceOf(MfaStoreError);
			expect((error as MfaStoreError).reason, what).toBe("malformed_answer");
		}
	});

	it("throws on a 200 whose body is not { factor }", async () => {
		for (const body of ["not json", "{}", "null", "[]"]) {
			fake.answer("update", () => json(200, body));
			const error = await rejection(storeOver().update("user-1", ID, 1, NEXT));
			expect((error as MfaStoreError).reason, body).toBe("malformed_answer");
		}
	});

	it("throws on any other status, a 204 and a redirect included", async () => {
		for (const status of [204, 201, 400, 500, 503, 307, 308]) {
			fake.answer("update", () => ({ status, headers: { Location: fake.urls.updateUrl } }));
			const error = await rejection(storeOver().update("user-1", ID, 1, NEXT));
			expect((error as MfaStoreError).reason, String(status)).toBe("unexpected_status");
			expect((error as MfaStoreError).operation).toBe("update");
		}
	});
});

describe("delete", () => {
	it("answers a 404 as done, for one record and for a subject's", async () => {
		fake.answer("delete", () => ({ status: 404 }));
		await expect(storeOver().remove("user-1", ID)).resolves.toBeUndefined();
		await expect(storeOver().removeAllForSubject("user-1")).resolves.toBeUndefined();
	});

	it("takes any 2xx as done", async () => {
		for (const status of [200, 202, 204]) {
			fake.answer("delete", () => ({ status, body: status === 204 ? undefined : "{}" }));
			await expect(storeOver().remove("user-1", ID), String(status)).resolves.toBeUndefined();
		}
	});

	it("throws on any other status, a redirect included", async () => {
		for (const status of [400, 409, 500, 503, 307]) {
			fake.answer("delete", () => ({ status, headers: { Location: fake.urls.deleteUrl } }));
			for (const call of [
				() => storeOver().remove("user-1", ID),
				() => storeOver().removeAllForSubject("user-1"),
			]) {
				const error = await rejection(call());
				expect((error as MfaStoreError).reason, String(status)).toBe("unexpected_status");
				expect((error as MfaStoreError).operation).toBe("delete");
			}
		}
	});
});

describe("nothing the Store sends reaches what it throws", () => {
	it("in a status line, a header or a body, whatever the operation and the status", async () => {
		let status = 500;
		let body = `{"error":"${MARKER}"}`;
		const origin = await serve((_request, _body, response) => {
			response.writeHead(status, MARKER, {
				"Content-Type": "application/json",
				"X-Store-Error": MARKER,
				"WWW-Authenticate": `Bearer error_description="${MARKER}"`,
				Location: `https://${MARKER}.example/`,
			});
			response.end(body);
		});
		const store = storeAt(origin);
		const calls = [
			() => store.list("user-1"),
			() => store.create(RECORD),
			() => store.update("user-1", ID, 1, NEXT),
			() => store.remove("user-1", ID),
		];
		let thrown = 0;
		for (const answer of [
			{ status: 500, body: `{"error":"${MARKER}"}` },
			{ status: 503, body: MARKER },
			{ status: 401, body: MARKER },
			{ status: 302, body: MARKER },
			{ status: 418, body: MARKER },
			{ status: 200, body: `${MARKER} is not JSON` },
			{ status: 200, body: JSON.stringify({ factors: [{ ...WIRE, id: MARKER }] }) },
			{ status: 200, body: JSON.stringify({ factor: { ...WIRE, id: MARKER, version: 2 } }) },
			{ status: 200, body: JSON.stringify({ factor: { ...WIRE, data: MARKER, version: 2 } }) },
		]) {
			status = answer.status;
			body = answer.body;
			for (const call of calls) {
				const error = await call().then(
					() => undefined,
					(thrown: Error) => thrown,
				);
				if (error === undefined) continue;
				thrown += 1;
				expect(everyForm(error), `${answer.status} ${answer.body}`).not.toContain(MARKER);
			}
		}
		// Create and delete take the four 200s as done; every other call throws.
		expect(thrown).toBe(9 * calls.length - 2 * 4);
	});

	it("in a credential refusal", async () => {
		const origin = await serve((_request, _body, response) => {
			response.writeHead(401, MARKER, {
				"WWW-Authenticate": `Bearer error="invalid_token", error_description="${MARKER}"`,
			});
			response.end(MARKER);
		});
		const error = await rejection(storeAt(origin, TOKEN).list("user-1"));
		expect(error).toBeInstanceOf(StoreCredentialRefusedError);
		expect(everyForm(error)).not.toContain(MARKER);
		expect(everyForm(error)).not.toContain(TOKEN);
	});
});

describe("the transport", () => {
	it("throws StoreCredentialRefusedError when the Store refuses the token with a Bearer challenge", async () => {
		const other = await startFakeStore({ bearerToken: `${TOKEN}ff` });
		try {
			const store = new HttpMfaFactorStore({ ...urlsOf(other), bearerToken: TOKEN, timeout: 5000 });
			for (const call of [
				() => store.list("user-1"),
				() => store.create(RECORD),
				() => store.update("user-1", ID, 1, NEXT),
				() => store.remove("user-1", ID),
			]) {
				const error = await rejection(call());
				expect(error).toBeInstanceOf(StoreCredentialRefusedError);
				expect((error as StoreCredentialRefusedError).storeStatus).toBe(401);
			}
		} finally {
			await other.close();
		}
	});

	it("throws a TimeoutError when the Store does not answer within the deadline", async () => {
		fake.answer("list", () => new Promise(() => {}));
		const error = await rejection(storeOver({ timeout: 200 }).list("user-1"));
		expect(error.name).toBe("TimeoutError");
		expect(error.message).toContain("timed out after 200ms");
	});

	it("refuses an answer over the response cap, quoting none of it", async () => {
		fake.answer("list", () => json(200, { factors: [], padding: MARKER.repeat(50) }));
		const error = await rejection(storeOver({ maxResponseBytes: 256 }).list("user-1"));
		expect(error.message).toContain("256-byte cap");
		expect(everyForm(error)).not.toContain(MARKER);
	});

	it("throws a StoreTransportError for a Store it cannot reach", async () => {
		const origin = await serve(() => {});
		const [server] = servers.splice(0, 1);
		await new Promise<void>((resolve) => server?.close(() => resolve()));
		const error = await rejection(storeAt(origin).list("user-1"));
		expect(error).toBeInstanceOf(StoreTransportError);
		expect((error as StoreTransportError).reason).toBe("unreachable");
	});
});

describe("construction", () => {
	it("is kind store", () => {
		expect(storeOver().kind).toBe("store");
	});

	it("refuses a URL that is not https or http to a loopback host, naming the option and quoting no value", () => {
		for (const key of ["listUrl", "createUrl", "updateUrl", "deleteUrl"] as const) {
			expect(() => storeOver({ [key]: "http://store.internal/mfa?key=SECRET" })).toThrow(key);
			let message = "";
			try {
				storeOver({ [key]: "https://user:SECRET@store.example/mfa" });
			} catch (error) {
				message = (error as Error).message;
			}
			expect(message).toContain(key);
			expect(message).not.toContain("SECRET");
		}
	});

	it("refuses a timeout, a response cap or a bearer token the user repository refuses", () => {
		for (const timeout of [0, -1, 1.5, Number.NaN, 2_147_483_648]) {
			expect(() => storeOver({ timeout }), String(timeout)).toThrow(/timeout/);
		}
		for (const maxResponseBytes of [0, -1, 1.5, Number.NaN]) {
			expect(() => storeOver({ maxResponseBytes }), String(maxResponseBytes)).toThrow(
				/maxResponseBytes/,
			);
		}
		for (const bearerToken of ["", "short", "Bearer abc", `${TOKEN}\n`]) {
			expect(() => storeOver({ bearerToken }), JSON.stringify(bearerToken)).toThrow(/bearerToken/);
		}
	});

	it("keeps the bearer token out of what inspecting or serialising the store shows", () => {
		const store = storeOver();
		expect(inspect(store, { depth: 5, showHidden: true })).not.toContain(TOKEN);
		expect(JSON.stringify(store)).not.toContain(TOKEN);
	});
});
