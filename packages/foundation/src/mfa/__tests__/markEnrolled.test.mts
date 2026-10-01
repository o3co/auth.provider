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
 * `HttpUserRepository.markMfaEnrolled` against the test kit's fake Store and
 * bare `node:http` servers: what the mark sends, which answer is done, and
 * that what a broken Store or transport makes it throw carries nothing the
 * Store sent, and neither the endpoint's query nor the body.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { inspect } from "node:util";
import {
	auditedError,
	loggableError,
	supportsMfaEnrollmentWitness,
} from "@o3co/auth-provider-core";
import { type FakeStore, startFakeStore } from "@o3co/auth-provider-test-kit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	HttpUserRepository,
	MfaStoreError,
	StoreCredentialRefusedError,
	StoreTransportError,
} from "#/index.mjs";

const TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SUBJECT = "user-1";

/** Text the Store wrote, which must reach nothing an error carries. */
const MARKER = "STORE-WROTE-THIS";
/** A query the endpoint is configured with, which no error names. */
const QUERY_SECRET = "tenant-key-QUERY";

let fake: FakeStore;
beforeEach(async () => {
	fake = await startFakeStore({
		bearerToken: TOKEN,
		users: [{ id: SUBJECT, username: "alice@example.com", password: "alice-password" }],
	});
});
afterEach(async () => {
	await fake.close();
});

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

/** The repository with `markMfaEnrolledUrl`, over the fake Store's user endpoints. */
const repositoryWith = (
	markMfaEnrolledUrl: string,
	overrides: Partial<ConstructorParameters<typeof HttpUserRepository>[0]> = {},
): HttpUserRepository =>
	new HttpUserRepository({
		authenticateUrl: fake.urls.authenticateUrl,
		authenticateByTokenUrl: fake.urls.authenticateByTokenUrl,
		markMfaEnrolledUrl,
		bearerToken: TOKEN,
		timeout: 5000,
		...overrides,
	});

/** The repository's `markMfaEnrolled`, which it has when the URL is configured. */
function markOf(repository: HttpUserRepository) {
	const { markMfaEnrolled } = repository;
	if (markMfaEnrolled === undefined) throw new Error("the repository has no markMfaEnrolled");
	return markMfaEnrolled;
}

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

describe("what a mark sends", () => {
	it("posts { subject, enrolled } as JSON to the URL as configured, with the bearer token", async () => {
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
			response.writeHead(204).end();
		});
		const mark = markOf(repositoryWith(`${origin}/mfa/enrolled?tenant=a`));
		await mark(SUBJECT, true);
		await mark(SUBJECT, false);
		expect(seen.map(({ method, url }) => [method, url])).toEqual([
			["POST", "/mfa/enrolled?tenant=a"],
			["POST", "/mfa/enrolled?tenant=a"],
		]);
		for (const request of seen) {
			expect(request.headers["content-type"]).toBe("application/json");
			expect(request.headers.authorization).toBe(`Bearer ${TOKEN}`);
		}
		expect(seen.map((request) => request.body)).toEqual([
			{ subject: SUBJECT, enrolled: true },
			{ subject: SUBJECT, enrolled: false },
		]);
	});

	it("sends no Authorization header without a bearer token", async () => {
		const authorizations: (string | undefined)[] = [];
		const origin = await serve((request, _body, response) => {
			authorizations.push(request.headers.authorization);
			response.writeHead(204).end();
		});
		const repository = new HttpUserRepository({
			authenticateUrl: `${origin}/authenticate`,
			authenticateByTokenUrl: `${origin}/authenticate-by-token`,
			markMfaEnrolledUrl: `${origin}/mfa/enrolled`,
			timeout: 5000,
		});
		await markOf(repository)(SUBJECT, true);
		expect(authorizations).toEqual([undefined]);
	});

	it("refuses, with a RangeError and sending nothing, a subject that is not a non-empty string or a value that is not a boolean", async () => {
		const mark = markOf(repositoryWith(fake.urls.markMfaEnrolledUrl));
		for (const [subject, enrolled] of [
			["", true],
			[42, true],
			[SUBJECT, "false"],
			[SUBJECT, 0],
			[SUBJECT, undefined],
		] as const) {
			const error = await rejection(mark(subject as never, enrolled as never));
			expect(error, JSON.stringify([subject, enrolled])).toBeInstanceOf(RangeError);
		}
		expect(fake.requests).toEqual([]);
	});
});

describe("the Store's answer", () => {
	it("is done on a 204, and the next login answers the witness", async () => {
		const repository = repositoryWith(fake.urls.markMfaEnrolledUrl);
		expect(await markOf(repository)(SUBJECT, true)).toBeUndefined();
		expect(fake.enrolled(SUBJECT)).toBe(true);
		expect(await repository.authenticate("alice@example.com", "alice-password")).toMatchObject({
			id: SUBJECT,
			mfaEnrolled: true,
		});
	});

	it("throws unknown_subject on a 404: the Store holds no such subject", async () => {
		const error = await rejection(
			markOf(repositoryWith(fake.urls.markMfaEnrolledUrl))("nobody", true),
		);
		expect(error).toBeInstanceOf(MfaStoreError);
		expect(error).toMatchObject({
			name: "MfaStoreError",
			reason: "unknown_subject",
			operation: "markMfaEnrolled",
			storeStatus: 404,
		});
	});

	it("throws unexpected_status on any other status — a 200, a 5xx, a 401 without a challenge, a redirect — and contacts no Location", async () => {
		let redirected = 0;
		const elsewhere = await serve((_request, _body, response) => {
			redirected += 1;
			response.writeHead(204).end();
		});
		for (const status of [200, 201, 400, 401, 409, 500, 503, 301, 302, 307, 308]) {
			fake.answer("markMfaEnrolled", () => ({
				status,
				headers: { Location: `${elsewhere}/mfa/enrolled` },
				body: status === 200 ? "{}" : undefined,
			}));
			const error = await rejection(
				markOf(repositoryWith(fake.urls.markMfaEnrolledUrl))(SUBJECT, true),
			);
			expect(error, String(status)).toBeInstanceOf(MfaStoreError);
			expect(error, String(status)).toMatchObject({
				reason: "unexpected_status",
				operation: "markMfaEnrolled",
				storeStatus: status,
			});
		}
		expect(redirected).toBe(0);
		expect(fake.enrolled(SUBJECT)).toBeUndefined();
	});
});

describe("nothing the Store sends, nor the query or the body, reaches what it throws", () => {
	it("in a status line, a header or a body, whatever the status", async () => {
		let status = 500;
		const origin = await serve((_request, _body, response) => {
			response.writeHead(status, MARKER, {
				"Content-Type": "application/json",
				"X-Store-Error": MARKER,
				"WWW-Authenticate": `Basic realm="${MARKER}"`,
				Location: `https://${MARKER}.example/`,
			});
			response.end(`{"error":"${MARKER}"}`);
		});
		const mark = markOf(repositoryWith(`${origin}/mfa/enrolled?key=${QUERY_SECRET}`));
		for (const answer of [200, 302, 401, 403, 404, 418, 500, 503]) {
			status = answer;
			const error = await rejection(mark(`subject-${MARKER}`, true));
			const forms = everyForm(error);
			expect(forms, String(answer)).not.toContain(MARKER);
			expect(forms, String(answer)).not.toContain(QUERY_SECRET);
			expect(forms, String(answer)).toContain(`${origin}/mfa/enrolled`);
		}
	});

	it("in a credential refusal: a 401 with a Bearer challenge throws StoreCredentialRefusedError, naming this repository", async () => {
		const origin = await serve((_request, _body, response) => {
			response.writeHead(401, MARKER, {
				"WWW-Authenticate": `Bearer error="invalid_token", error_description="${MARKER}"`,
			});
			response.end(MARKER);
		});
		const error = await rejection(
			markOf(repositoryWith(`${origin}/mfa/enrolled?key=${QUERY_SECRET}`))(SUBJECT, true),
		);
		expect(error).toBeInstanceOf(StoreCredentialRefusedError);
		expect((error as StoreCredentialRefusedError).storeStatus).toBe(401);
		expect(error.message.startsWith("HttpUserRepository: ")).toBe(true);
		for (const hidden of [MARKER, TOKEN, QUERY_SECRET]) {
			expect(everyForm(error)).not.toContain(hidden);
		}
	});
});

describe("the transport", () => {
	it("throws StoreCredentialRefusedError when the fake Store refuses the token", async () => {
		const error = await rejection(
			markOf(repositoryWith(fake.urls.markMfaEnrolledUrl, { bearerToken: `${TOKEN}ff` }))(
				SUBJECT,
				true,
			),
		);
		expect(error).toBeInstanceOf(StoreCredentialRefusedError);
		expect(fake.enrolled(SUBJECT)).toBeUndefined();
	});

	it("throws a TimeoutError when the Store does not answer within the deadline", async () => {
		fake.answer("markMfaEnrolled", () => new Promise(() => {}));
		const error = await rejection(
			markOf(repositoryWith(fake.urls.markMfaEnrolledUrl, { timeout: 200 }))(SUBJECT, true),
		);
		expect(error.name).toBe("TimeoutError");
		expect(error.message).toContain("timed out after 200ms");
	});

	it("throws a StoreTransportError for a Store it cannot reach, carrying neither the query nor the body", async () => {
		const origin = await serve(() => {});
		const [server] = servers.splice(0, 1);
		await new Promise<void>((resolve) => server?.close(() => resolve()));
		const error = await rejection(
			markOf(repositoryWith(`${origin}/mfa/enrolled?key=${QUERY_SECRET}`))(
				`subject-${MARKER}`,
				true,
			),
		);
		expect(error).toBeInstanceOf(StoreTransportError);
		expect((error as StoreTransportError).reason).toBe("unreachable");
		expect(everyForm(error)).not.toContain(QUERY_SECRET);
		expect(everyForm(error)).not.toContain(MARKER);
	});
});

describe("presence", () => {
	it("is absent without markMfaEnrolledUrl, and detected by supportsMfaEnrollmentWitness with it", () => {
		const without = new HttpUserRepository({
			authenticateUrl: "https://store.example/authenticate",
			authenticateByTokenUrl: "https://store.example/authenticate-by-token",
			timeout: 5000,
		});
		expect(without.markMfaEnrolled).toBeUndefined();
		expect(supportsMfaEnrollmentWitness(without)).toBe(false);
		const withUrl = new HttpUserRepository({
			authenticateUrl: "https://store.example/authenticate",
			authenticateByTokenUrl: "https://store.example/authenticate-by-token",
			markMfaEnrolledUrl: "https://store.example/mfa/enrolled",
			timeout: 5000,
		});
		expect(supportsMfaEnrollmentWitness(withUrl)).toBe(true);
	});

	it("refuses a URL that is not https or http to a loopback host, or one carrying credentials, naming the option and quoting no value", () => {
		for (const url of [
			"http://store.internal/mfa/enrolled",
			"http://10.0.0.5/mfa/enrolled",
			`https://user:${QUERY_SECRET}@store.example/mfa/enrolled`,
			"ftp://store.example/mfa/enrolled",
			"",
		]) {
			expect(
				() =>
					new HttpUserRepository({
						authenticateUrl: "https://store.example/authenticate",
						authenticateByTokenUrl: "https://store.example/authenticate-by-token",
						markMfaEnrolledUrl: url,
						timeout: 5000,
					}),
				url,
			).toThrow(/^HttpUserRepository: "markMfaEnrolledUrl" /);
			try {
				new HttpUserRepository({
					authenticateUrl: "https://store.example/authenticate",
					authenticateByTokenUrl: "https://store.example/authenticate-by-token",
					markMfaEnrolledUrl: url,
					timeout: 5000,
				});
			} catch (error) {
				expect((error as Error).message).not.toContain(QUERY_SECRET);
			}
		}
	});

	it("keeps the bearer token out of what inspecting or serialising the repository shows", () => {
		const repository = repositoryWith(fake.urls.markMfaEnrolledUrl);
		expect(inspect(repository, { depth: 5 })).not.toContain(TOKEN);
		expect(JSON.stringify(repository)).not.toContain(TOKEN);
	});
});
