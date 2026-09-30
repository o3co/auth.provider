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
 * The fake Store over real HTTP on a loopback address: what a Store answers
 * on each MFA endpoint, and on the two login endpoints the witness is read
 * back through. Every record it holds is answered back, readable or not; an
 * update is a compare-and-set that writes the changes and nothing else of
 * the record, at the expected version plus one; the witness mark is `204`,
 * idempotent, and `404` for a subject it does not hold. It refuses a body
 * not declared JSON, a request naming another host or an absolute target,
 * and a body over 1 MiB, before it records the request. Told to, it answers
 * an endpoint otherwise — later, or never — so an adapter's reading of a
 * Store that breaks the contract can be tested.
 */

import { request as httpRequest } from "node:http";
import {
	type MfaFactorRecord,
	type MfaStoreFactor,
	toMfaStoreFactor,
	toMfaStoreUpdateRequest,
} from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it } from "vitest";
import { type FakeStore, startFakeStore } from "#/index.mjs";

/** Factor ids as the provider makes them: 16 random bytes, base64url. */
const ID_1 = "u1PIlRkb_cy7UmjYUKaL_A";
const ID_2 = "TO-Ylhtepgp2qoDTXRcOnQ";
const ID_GONE = "f1G-RUIhmJ-Y4ZanyCo3KA";

const RECORD: MfaFactorRecord = {
	id: ID_1,
	subject: "user-1",
	kind: "totp",
	label: "Phone",
	binding: "password",
	createdAt: new Date("2026-09-01T00:00:00.000Z"),
	lastUsedAt: new Date("2026-09-02T00:00:00.000Z"),
	version: 1,
	data: "v2.opaque-sealed-data",
};
const WIRE: MfaStoreFactor = toMfaStoreFactor(RECORD);

const USERS = [
	{ id: "user-1", username: "alice", password: "alice-password" },
	{ id: "user-2", username: "bob", password: "bob-password", claims: { email: "bob@example.com" } },
] as const;

let store: FakeStore | undefined;
afterEach(async () => {
	await store?.close();
	store = undefined;
});

async function start(options: Parameters<typeof startFakeStore>[0] = { users: USERS }) {
	store = await startFakeStore(options);
	return store;
}

/** POST `body` as JSON to `url`, answering the status, the headers and the body as parsed JSON (or text). */
async function post(url: string, body: unknown, headers: Record<string, string> = {}) {
	const response = await fetch(url, {
		method: "POST",
		headers: { "Content-Type": "application/json", ...headers },
		body: typeof body === "string" ? body : JSON.stringify(body),
		redirect: "manual",
	});
	const text = await response.text();
	let json: unknown;
	try {
		json = text === "" ? undefined : JSON.parse(text);
	} catch {
		json = text;
	}
	return { status: response.status, headers: response.headers, body: json, text };
}

describe("the fake Store's URLs", () => {
	it("are loopback http URLs, one per endpoint", async () => {
		const { urls } = await start();
		expect(Object.keys(urls).sort()).toEqual(
			[
				"authenticateByTokenUrl",
				"authenticateUrl",
				"createUrl",
				"deleteUrl",
				"listUrl",
				"markMfaEnrolledUrl",
				"updateUrl",
			].sort(),
		);
		for (const url of Object.values(urls)) expect(url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\//);
		expect(new Set(Object.values(urls)).size).toBe(7);
	});

	it("answer anything but a POST with 405, and an unknown path with 404", async () => {
		const { urls } = await start();
		expect((await fetch(urls.listUrl)).status).toBe(405);
		expect((await post(`${new URL(urls.listUrl).origin}/nowhere`, {})).status).toBe(404);
	});
});

describe("list", () => {
	it("answers 200 with every record held for the subject, and an empty list for a subject with none", async () => {
		const { urls } = await start();
		expect(await post(urls.listUrl, { subject: "user-1" })).toMatchObject({
			status: 200,
			body: { factors: [] },
		});
		await post(urls.createUrl, { factor: WIRE });
		expect(await post(urls.listUrl, { subject: "user-1" })).toMatchObject({
			status: 200,
			body: { factors: [WIRE] },
		});
		expect((await post(urls.listUrl, { subject: "user-2" })).body).toEqual({ factors: [] });
	});

	it("answers back a record it holds whatever it is, one the provider cannot read included", async () => {
		const fake = await start();
		const unreadable = { ...WIRE, id: ID_2, label: null, createdAtMs: "yesterday" };
		fake.holdFactor("user-1", WIRE);
		fake.holdFactor("user-1", unreadable);
		expect((await post(fake.urls.listUrl, { subject: "user-1" })).body).toEqual({
			factors: [WIRE, unreadable],
		});
		expect(fake.factors("user-1")).toEqual([WIRE, unreadable]);
	});

	it("answers 400 to a body that is not { subject }", async () => {
		const { urls } = await start();
		for (const body of [{}, { subject: 1 }, [], "not json", "null"]) {
			expect((await post(urls.listUrl, body)).status, JSON.stringify(body)).toBe(400);
		}
	});
});

describe("create", () => {
	it("answers 204 and holds the record as sent: data byte for byte, an absent field absent", async () => {
		const fake = await start();
		const bare = toMfaStoreFactor({
			...RECORD,
			id: ID_2,
			label: undefined,
			binding: undefined,
			lastUsedAt: undefined,
			data: '{"a":[],"b":{}} ü∆ 漢字 🙂',
		});
		expect((await post(fake.urls.createUrl, { factor: bare })).status).toBe(204);
		expect(fake.factors("user-1")).toStrictEqual([bare]);
		const listed = await post(fake.urls.listUrl, { subject: "user-1" });
		expect(listed.text).not.toContain("null");
	});

	it("answers 409 to a duplicate (subject, id), keeping the record held", async () => {
		const fake = await start();
		await post(fake.urls.createUrl, { factor: WIRE });
		expect(
			(await post(fake.urls.createUrl, { factor: { ...WIRE, data: "v2.other" } })).status,
		).toBe(409);
		expect(
			(await post(fake.urls.createUrl, { factor: { ...WIRE, subject: "user-2" } })).status,
		).toBe(204);
		expect(fake.factors("user-1")).toStrictEqual([WIRE]);
	});

	it("answers 400 to a record that is not one, null for an optional field included, and holds nothing", async () => {
		const fake = await start();
		for (const factor of [{ ...WIRE, label: null }, { ...WIRE, createdAtMs: "x" }, {}, null]) {
			expect((await post(fake.urls.createUrl, { factor })).status, JSON.stringify(factor)).toBe(
				400,
			);
		}
		expect(fake.factors("user-1")).toEqual([]);
	});
});

describe("update", () => {
	const next = {
		data: "v2.re-sealed",
		label: "Work phone",
		lastUsedAt: new Date("2026-09-03T00:00:00.000Z"),
	};

	it("writes the changes at the expected version, answering the record at that version plus one, nothing else of it moved", async () => {
		const fake = await start();
		fake.holdFactor("user-1", WIRE);
		const answer = await post(
			fake.urls.updateUrl,
			toMfaStoreUpdateRequest("user-1", ID_1, 1, next),
		);
		const written = {
			...WIRE,
			data: "v2.re-sealed",
			label: "Work phone",
			lastUsedAtMs: next.lastUsedAt.getTime(),
			version: 2,
		};
		expect(answer).toMatchObject({ status: 200, body: { factor: written } });
		expect(fake.factors("user-1")).toStrictEqual([written]);
	});

	it("clears a label and a lastUsedAtMs the changes leave out", async () => {
		const fake = await start();
		fake.holdFactor("user-1", WIRE);
		const answer = await post(
			fake.urls.updateUrl,
			toMfaStoreUpdateRequest("user-1", ID_1, 1, {
				data: "v2.x",
				label: undefined,
				lastUsedAt: undefined,
			}),
		);
		const { label: _label, lastUsedAtMs: _lastUsedAtMs, ...kept } = WIRE;
		expect(answer.body).toStrictEqual({ factor: { ...kept, data: "v2.x", version: 2 } });
	});

	it("answers 409 for a version that moved, and 404 for a record that is gone, changing nothing", async () => {
		const fake = await start();
		fake.holdFactor("user-1", WIRE);
		for (const expectedVersion of [0, 2]) {
			const moved = toMfaStoreUpdateRequest("user-1", ID_1, expectedVersion, next);
			expect((await post(fake.urls.updateUrl, moved)).status).toBe(409);
		}
		expect(
			(await post(fake.urls.updateUrl, toMfaStoreUpdateRequest("user-2", ID_1, 1, next))).status,
		).toBe(404);
		expect(
			(await post(fake.urls.updateUrl, toMfaStoreUpdateRequest("user-1", ID_GONE, 1, next))).status,
		).toBe(404);
		expect(fake.factors("user-1")).toStrictEqual([WIRE]);
	});

	it("answers 400 to changes carrying a field a Store must not change, changing nothing", async () => {
		const fake = await start();
		fake.holdFactor("user-1", WIRE);
		const request = toMfaStoreUpdateRequest("user-1", ID_1, 1, next);
		for (const field of ["id", "subject", "kind", "binding", "createdAtMs", "version"]) {
			const forged = { ...request, changes: { ...request.changes, [field]: "forged" } };
			expect((await post(fake.urls.updateUrl, forged)).status, field).toBe(400);
		}
		for (const expectedVersion of [-1, 1.5, Number.MAX_SAFE_INTEGER, "1"]) {
			expect(
				(await post(fake.urls.updateUrl, { ...request, expectedVersion })).status,
				String(expectedVersion),
			).toBe(400);
		}
		expect(fake.factors("user-1")).toStrictEqual([WIRE]);
	});

	it("lets exactly one of concurrent updates at one version through", async () => {
		const fake = await start();
		fake.holdFactor("user-1", WIRE);
		const answers = await Promise.all(
			Array.from({ length: 10 }, (_, i) =>
				post(
					fake.urls.updateUrl,
					toMfaStoreUpdateRequest("user-1", ID_1, 1, { ...next, data: `v2.writer-${i}` }),
				),
			),
		);
		expect(answers.filter((answer) => answer.status === 200)).toHaveLength(1);
		expect(answers.filter((answer) => answer.status === 409)).toHaveLength(9);
	});
});

describe("delete", () => {
	it("answers 204 for one record or every record of a subject, and 404 when it held none", async () => {
		const fake = await start();
		fake.holdFactor("user-1", WIRE);
		fake.holdFactor("user-1", { ...WIRE, id: ID_2 });
		fake.holdFactor("user-2", WIRE);
		expect((await post(fake.urls.deleteUrl, { subject: "user-1", id: ID_1 })).status).toBe(204);
		expect((await post(fake.urls.deleteUrl, { subject: "user-1", id: ID_1 })).status).toBe(404);
		expect(fake.factors("user-1")).toStrictEqual([{ ...WIRE, id: ID_2 }]);
		expect((await post(fake.urls.deleteUrl, { subject: "user-1", all: true })).status).toBe(204);
		expect((await post(fake.urls.deleteUrl, { subject: "user-1", all: true })).status).toBe(404);
		expect(fake.factors("user-1")).toEqual([]);
		expect(fake.factors("user-2")).toStrictEqual([WIRE]);
	});

	it("answers 400 to a body that names neither one record nor all", async () => {
		const { urls } = await start();
		for (const body of [{ subject: "user-1" }, { subject: "user-1", all: "yes" }, { id: "x" }]) {
			expect((await post(urls.deleteUrl, body)).status, JSON.stringify(body)).toBe(400);
		}
	});
});

describe("markMfaEnrolled and the login it is read back through", () => {
	it("answers 204 and holds the witness, which authenticate answers as mfaEnrolled", async () => {
		const fake = await start();
		expect(fake.enrolled("user-1")).toBeUndefined();
		const before = await post(fake.urls.authenticateUrl, {
			email: "alice",
			password: "alice-password",
		});
		expect(before).toMatchObject({ status: 200, body: { id: "user-1", username: "alice" } });
		expect(before.body).not.toHaveProperty("mfaEnrolled");
		expect(
			(await post(fake.urls.markMfaEnrolledUrl, { subject: "user-1", enrolled: true })).status,
		).toBe(204);
		expect(fake.enrolled("user-1")).toBe(true);
		const after = await post(fake.urls.authenticateUrl, {
			email: "alice",
			password: "alice-password",
		});
		expect(after.body).toEqual({ id: "user-1", username: "alice", mfaEnrolled: true });
	});

	it("is idempotent: marking the value already held is 204 again", async () => {
		const fake = await start();
		for (const enrolled of [true, true, false, false]) {
			expect(
				(await post(fake.urls.markMfaEnrolledUrl, { subject: "user-2", enrolled })).status,
			).toBe(204);
			expect(fake.enrolled("user-2")).toBe(enrolled);
		}
	});

	it("answers 404 for a subject it does not hold, and marks nobody", async () => {
		const fake = await start();
		expect(
			(await post(fake.urls.markMfaEnrolledUrl, { subject: "nobody", enrolled: true })).status,
		).toBe(404);
		expect(fake.enrolled("nobody")).toBeUndefined();
		expect(fake.enrolled("user-1")).toBeUndefined();
	});

	it("answers 400 to a body that is not { subject, enrolled: boolean }", async () => {
		const { urls } = await start();
		for (const body of [{ subject: "user-1" }, { subject: "user-1", enrolled: "true" }, {}]) {
			expect((await post(urls.markMfaEnrolledUrl, body)).status, JSON.stringify(body)).toBe(400);
		}
	});

	it("answers 401 to a login it does not hold, and answers a user's other fields", async () => {
		const { urls } = await start();
		expect((await post(urls.authenticateUrl, { email: "alice", password: "wrong" })).status).toBe(
			401,
		);
		expect((await post(urls.authenticateUrl, { email: "carol", password: "x" })).status).toBe(401);
		expect((await post(urls.authenticateByTokenUrl, { token: "github:1" })).status).toBe(401);
		expect(
			(await post(urls.authenticateUrl, { email: "bob", password: "bob-password" })).body,
		).toEqual({ id: "user-2", username: "bob", email: "bob@example.com" });
	});
});

/** A raw request to the fake Store, with the request line and headers as given. */
function raw(
	port: number,
	options: {
		readonly path: string;
		readonly headers: Record<string, string>;
		readonly body?: string;
	},
): Promise<number> {
	return new Promise((resolve, reject) => {
		const request = httpRequest(
			{ host: "127.0.0.1", port, method: "POST", path: options.path, headers: options.headers },
			(response) => {
				response.resume();
				resolve(response.statusCode ?? 0);
			},
		);
		request.on("error", reject);
		request.end(options.body ?? "{}");
	});
}

describe("what the fake Store refuses before it reads a request", () => {
	it("answers 415 to a body that is not declared JSON", async () => {
		const { urls } = await start();
		for (const type of ["text/plain", "application/x-www-form-urlencoded", "application/jsonx"]) {
			const response = await fetch(urls.markMfaEnrolledUrl, {
				method: "POST",
				headers: { "Content-Type": type },
				body: JSON.stringify({ subject: "user-1", enrolled: true }),
			});
			expect(response.status, type).toBe(415);
		}
		const declared = await fetch(urls.listUrl, {
			method: "POST",
			headers: { "Content-Type": "Application/JSON; charset=utf-8" },
			body: JSON.stringify({ subject: "user-1" }),
		});
		expect(declared.status).toBe(200);
	});

	it("answers 421 to a request naming another host, and 400 to an absolute or odd request target", async () => {
		const fake = await start();
		const { port } = new URL(fake.urls.listUrl);
		const json = { "Content-Type": "application/json" };
		expect(
			await raw(Number(port), {
				path: "/mfa/factors/list",
				headers: { ...json, Host: "rebind.attacker.example" },
			}),
		).toBe(421);
		expect(
			await raw(Number(port), {
				path: "http://other.example/mfa/factors/list",
				headers: { ...json, Host: `127.0.0.1:${port}` },
			}),
		).toBe(400);
		expect(
			await raw(Number(port), { path: "//", headers: { ...json, Host: `127.0.0.1:${port}` } }),
		).toBe(400);
		expect(fake.requests).toEqual([]);
	});

	it("answers 413 to a body over 1 MiB, holding none of it", async () => {
		const fake = await start();
		const answer = await post(fake.urls.listUrl, {
			subject: "user-1",
			pad: "x".repeat(1024 * 1024),
		});
		expect(answer.status).toBe(413);
		expect(fake.requests).toEqual([]);
	});
});

describe("the fake Store's credential", () => {
	it("with a bearer token, answers 401 with a Bearer challenge to a request without it, and serves one with it", async () => {
		const token = "0328d706529061d93abd6d826e09ef0f0a1e71a12af813b29e5cd2977b7dc63a";
		const { urls } = await start({ users: USERS, bearerToken: token });
		const refusedHeaders: Record<string, string>[] = [
			{},
			{ Authorization: "Bearer wrong" },
			{ Authorization: token },
		];
		for (const headers of refusedHeaders) {
			const refused = await post(urls.listUrl, { subject: "user-1" }, headers);
			expect(refused.status).toBe(401);
			expect(refused.headers.get("www-authenticate")).toBe('Bearer error="invalid_token"');
		}
		const served = await post(
			urls.listUrl,
			{ subject: "user-1" },
			{ Authorization: `Bearer ${token}` },
		);
		expect(served.status).toBe(200);
	});
});

describe("what the fake Store records and how it can be told to answer", () => {
	it("records every request: its endpoint, its headers and its body as parsed", async () => {
		const fake = await start();
		await post(fake.urls.listUrl, { subject: "user-1" }, { "X-Trace": "t-1" });
		expect(fake.requests).toHaveLength(1);
		expect(fake.requests[0]).toMatchObject({
			endpoint: "list",
			body: { subject: "user-1" },
			headers: { "x-trace": "t-1", "content-type": "application/json" },
		});
	});

	it("answers an endpoint as told while told to, and by the contract again once released", async () => {
		const fake = await start();
		fake.holdFactor("user-1", WIRE);
		const skipped = { ...WIRE, version: 3 };
		fake.answer("update", () => ({
			status: 200,
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ factor: skipped }),
		}));
		const request = toMfaStoreUpdateRequest("user-1", ID_1, 1, { ...RECORD });
		expect(await post(fake.urls.updateUrl, request)).toMatchObject({
			status: 200,
			body: { factor: skipped },
		});
		expect(fake.factors("user-1")).toStrictEqual([WIRE]);
		fake.answer("update", undefined);
		expect((await post(fake.urls.updateUrl, request)).body).toMatchObject({
			factor: { version: 2 },
		});
	});

	it("serves an answer it is told to give later once it comes, and holds a request it is never told to answer", async () => {
		const fake = await start();
		fake.answer("list", async () => {
			await new Promise((resolve) => setTimeout(resolve, 50));
			return { status: 503 };
		});
		expect((await post(fake.urls.listUrl, { subject: "user-1" })).status).toBe(503);
		fake.answer("list", () => new Promise(() => {}));
		await expect(
			fetch(fake.urls.listUrl, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ subject: "user-1" }),
				signal: AbortSignal.timeout(200),
			}),
		).rejects.toMatchObject({ name: "TimeoutError" });
	});

	it("falls back to the contract when the answer it was told gives none for a request", async () => {
		const fake = await start();
		fake.answer("markMfaEnrolled", (request) =>
			(request.body as { subject?: unknown }).subject === "user-1" ? { status: 503 } : undefined,
		);
		expect(
			(await post(fake.urls.markMfaEnrolledUrl, { subject: "user-1", enrolled: true })).status,
		).toBe(503);
		expect(
			(await post(fake.urls.markMfaEnrolledUrl, { subject: "user-2", enrolled: true })).status,
		).toBe(204);
		expect(fake.enrolled("user-1")).toBeUndefined();
	});
});
