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
 * The credential auth.provider presents to the Store, against real
 * `node:http` servers: with `bearerToken` configured every one of the four
 * requests carries `Authorization: Bearer <token>`, and without it none
 * carries an `Authorization` header at all. A token the constructor would not
 * stand behind — below core's shared-secret floor, not a bare RFC 6750 token,
 * blank, or not a string — is refused at construction, from config as by
 * hand; and the token appears in nothing the repository throws and in no
 * inspection of the repository itself.
 *
 * And the other direction: with a token configured, a `401` carrying a
 * `Bearer` challenge (RFC 6750 §3) is the Store refusing this deployment, so
 * every one of the four requests throws it as an outage naming that cause; a
 * `401` without one — or any `401` when no token is configured — keeps the
 * meaning the wire contract gives it.
 *
 * Without msw: what is asserted is the header that reaches the socket, and an
 * interceptor is one more thing between the two.
 */

import { createServer, type Server } from "node:http";
import { inspect } from "node:util";
import {
	createAdapterFactory,
	type FederatedIdentityLink,
	type UserRepository,
} from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it } from "vitest";
import { registerBuiltinAdapters } from "#/index.mjs";
import { HttpUserRepository } from "#/repositories/HttpUserRepository.mjs";

/** 32 bytes of key material, hex — what `openssl rand -hex 32` prints. */
const TOKEN = "0328d706529061d93abd6d826e09ef0f0a1e71a12af813b29e5cd2977b7dc63a";
/** 32 bytes of key material, base64 — what `openssl rand -base64 32` prints. */
const BASE64_TOKEN = "CzBVep/E6Q4zWH2ix+wRNluApcrvFDleg6jN8hc8YYY=";

const REG = {
	provider: "entra-files",
	issuer: "https://login.microsoftonline.com/T-1/v2.0",
	clientId: "grants-client",
};
const IDENTITY = { ...REG, sub: "pairwise-B", claims: { tid: "T-1", oid: "O-B" } };
const LINK: FederatedIdentityLink = {
	provider: "apple",
	sub: "a1",
	token: "apple:a1",
	claims: { email: "a@example.com", emailVerified: true },
};

let httpServers: Server[] = [];
afterEach(async () => {
	await Promise.all(
		httpServers.map((server) => {
			server.closeAllConnections();
			return new Promise<void>((resolve) => server.close(() => resolve()));
		}),
	);
	httpServers = [];
});

/** Starts a server on its own loopback port and returns its origin. */
const serve = async (handler: Parameters<typeof createServer>[1]): Promise<string> => {
	const server = createServer(handler);
	httpServers.push(server);
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as { port: number };
	return `http://127.0.0.1:${port}`;
};

/** What the Store saw of one request: the path, and the Authorization header if any. */
interface Heard {
	readonly path: string | undefined;
	readonly authorization: string | undefined;
}

/**
 * A Store that records the Authorization header of every request and answers
 * with a body each of the four accepts — a `User` that is also a lookup answer.
 */
const recordingStore = async (): Promise<{ origin: string; heard: Heard[] }> => {
	const heard: Heard[] = [];
	const origin = await serve((req, res) => {
		req.resume();
		req.on("end", () => {
			heard.push({ path: req.url, authorization: req.headers.authorization });
			res.writeHead(200, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ id: "user-1", username: "alice", kind: "unlinked" }));
		});
	});
	return { origin, heard };
};

const urls = (origin: string) => ({
	authenticateUrl: `${origin}/authenticate`,
	authenticateByTokenUrl: `${origin}/authenticate/token`,
	linkFederatedIdentityUrl: `${origin}/link`,
	findSubjectByFederatedIdentityUrl: `${origin}/lookup`,
	federatedIdentityLookupCoverage: [{ ...REG, requiredClaims: ["tid", "oid"] }],
});

const calls = [
	["authenticate", "/authenticate", (r: UserRepository) => r.authenticate("alice", "pass")],
	[
		"authenticateByToken",
		"/authenticate/token",
		(r: UserRepository) => r.authenticateByToken("apple:a1"),
	],
	["linkFederatedIdentity", "/link", (r: UserRepository) => r.linkFederatedIdentity?.("u1", LINK)],
	[
		"findSubjectByFederatedIdentity",
		"/lookup",
		(r: UserRepository) => r.findSubjectByFederatedIdentity?.(IDENTITY),
	],
] as const;

/** Everything an error could surface to a log line: its message, stack and whole cause chain. */
const surfaced = (error: unknown): string =>
	inspect(error, { depth: Number.POSITIVE_INFINITY, showHidden: true });

describe("every request carries the configured credential", () => {
	it.each(calls)("%s: sends Authorization: Bearer <token>", async (_name, path, call) => {
		const { origin, heard } = await recordingStore();
		const repo = new HttpUserRepository({ ...urls(origin), bearerToken: TOKEN, timeout: 5000 });

		await call(repo);

		expect(heard).toEqual([{ path, authorization: `Bearer ${TOKEN}` }]);
	});

	it.each(calls)(
		"%s: sends no Authorization header when no token is configured — the default is unchanged",
		async (_name, path, call) => {
			const { origin, heard } = await recordingStore();
			const repo = new HttpUserRepository({ ...urls(origin), timeout: 5000 });

			await call(repo);

			expect(heard).toEqual([{ path, authorization: undefined }]);
		},
	);

	it("sends a base64 token exactly as configured", async () => {
		const { origin, heard } = await recordingStore();
		const repo = new HttpUserRepository({
			...urls(origin),
			bearerToken: BASE64_TOKEN,
			timeout: 5000,
		});

		await repo.authenticate("alice", "pass");

		expect(heard).toEqual([{ path: "/authenticate", authorization: `Bearer ${BASE64_TOKEN}` }]);
	});
});

describe("a token the constructor would not stand behind is refused at construction", () => {
	const construct = (bearerToken: unknown) => () =>
		new HttpUserRepository({
			authenticateUrl: "https://users.example.com/authenticate",
			authenticateByTokenUrl: "https://users.example.com/authenticate-by-token",
			bearerToken: bearerToken as string,
			timeout: 5000,
		});

	/** The construction error, which must exist and must not quote `secret`. */
	const refusal = (bearerToken: unknown, secret: string): string => {
		let message: string | undefined;
		try {
			construct(bearerToken)();
		} catch (error) {
			message = surfaced(error);
		}
		expect(message, "construction should have been refused").toBeDefined();
		expect(message).not.toContain(secret);
		return message as string;
	};

	it("refuses a token below core's 32-byte shared-secret floor, measured on its decoded length", () => {
		// The same measurement SESSION_SECRET and OAUTH_JWT_SECRET get: a hex
		// string counts half its characters, so `openssl rand -hex 16` is 16
		// bytes however long it looks.
		for (const weak of [
			"s3cr3t-store-token",
			"0328d706529061d93abd6d826e09ef0f", // openssl rand -hex 16
			TOKEN.slice(0, 62), // 31 bytes
		]) {
			const message = refusal(weak, weak);
			expect(message).toMatch(/repositories\.user\.http\.bearerToken/);
			expect(message).toMatch(/at least 32 bytes/);
			expect(message).toMatch(/CLIENT_USER_BEARER_TOKEN/);
		}
	});

	it("accepts a token at the floor, hex or base64", () => {
		expect(construct(TOKEN)).not.toThrow();
		expect(construct(BASE64_TOKEN)).not.toThrow();
	});

	it("refuses what is not a bare RFC 6750 token — a scheme, whitespace, a line break, a non-ASCII character — without echoing it", () => {
		// A value fetch would refuse as a header is also a value fetch would
		// QUOTE in its TypeError, on the request path; so it is refused here,
		// where the message is ours and names only the option.
		for (const malformed of [
			`Bearer ${TOKEN}`,
			`${TOKEN} `,
			` ${TOKEN}`,
			`${TOKEN}\r\nX-Injected: 1`,
			`${TOKEN}\n`,
			`${TOKEN}é`,
			`${TOKEN.slice(0, 32)}=${TOKEN.slice(32)}`,
		]) {
			const message = refusal(malformed, TOKEN);
			expect(message).toMatch(/"bearerToken"/);
			expect(message).toMatch(/RFC 6750/);
		}
	});

	it('refuses a blank token — HOCON substitutes an exported-but-empty variable as ""', () => {
		expect(refusal("", TOKEN)).toMatch(/"bearerToken" must not be empty/);
	});

	it("refuses a token that is not a string", () => {
		for (const wrong of [42, true, null, { token: TOKEN }, [TOKEN]]) {
			expect(refusal(wrong, TOKEN)).toMatch(/"bearerToken" must be a string/);
		}
	});
});

describe("the token is in nothing the repository throws, and in no inspection of it", () => {
	/** A loopback port nothing listens on: bound, then closed. */
	const closedPort = async (): Promise<string> => {
		const server = createServer();
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		const { port } = server.address() as { port: number };
		await new Promise<void>((resolve) => server.close(() => resolve()));
		return `http://127.0.0.1:${port}`;
	};

	const answering =
		(status: number, body: string): Parameters<typeof createServer>[1] =>
		(req, res) => {
			req.resume();
			req.on("end", () => {
				res.writeHead(status, { "Content-Type": "application/json" });
				res.end(body);
			});
		};

	it.each(calls)("%s: no failure carries it", async (_name, _path, call) => {
		const failures: Record<string, () => Promise<string>> = {
			"a 500": () => serve(answering(500, "{}")),
			"a non-JSON 2xx": () => serve(answering(200, "not json")),
			"a 2xx that is neither a User nor an answer": () =>
				serve(answering(200, JSON.stringify({ status: "ok" }))),
			"a redirect": () => serve(answering(307, "")),
			"a refused connection": closedPort,
			"a Store that never answers": () =>
				serve((req) => {
					req.resume();
				}),
		};
		const seen: string[] = [];
		for (const [what, origin] of Object.entries(failures)) {
			const repo = new HttpUserRepository({
				...urls(await origin()),
				bearerToken: TOKEN,
				timeout: 300,
			});
			const outcome = await Promise.resolve(call(repo)).then(
				() => undefined,
				(error: unknown) => error,
			);
			expect(outcome, `${what} should have thrown`).toBeInstanceOf(Error);
			seen.push(surfaced(outcome));
		}
		expect(seen.filter((text) => text.includes(TOKEN))).toEqual([]);
	});

	it("keeps it out of the repository's own inspection and serialisation", () => {
		// A repository handed to a logger — `logger.info({ repo })`, a debug
		// dump of the component map — prints what inspect() and JSON.stringify
		// see. The token is not among it.
		const repo = new HttpUserRepository({
			...urls("https://users.example.com"),
			bearerToken: TOKEN,
			timeout: 5000,
		});
		expect(inspect(repo, { depth: Number.POSITIVE_INFINITY, showHidden: true })).not.toContain(
			TOKEN,
		);
		expect(JSON.stringify(repo)).not.toContain(TOKEN);
		expect(Object.values(repo).map(String).join("\n")).not.toContain(TOKEN);
	});
});

describe("a Store that refuses this deployment's credential", () => {
	/**
	 * A Store that answers every request `401`, with these `WWW-Authenticate`
	 * header lines (none when empty) and a body that says why — which nothing
	 * thrown may repeat.
	 */
	const refusingStore = (challenges: readonly string[]) =>
		serve((req, res) => {
			req.resume();
			req.on("end", () => {
				res.writeHead(401, {
					"Content-Type": "application/json",
					...(challenges.length === 0 ? {} : { "WWW-Authenticate": [...challenges] }),
				});
				res.end(JSON.stringify({ error: "invalid_token", error_description: "who are you" }));
			});
		});

	const INVALID_TOKEN = 'Bearer error="invalid_token", error_description="who are you"';

	/** What the four answer a `401` that is not a refused credential: the wire contract, unchanged. */
	const expectWireMeaningOf401 = async (repo: HttpUserRepository, origin: string) => {
		await expect(repo.authenticate("alice", "pass")).resolves.toBeNull();
		await expect(repo.authenticateByToken("apple:a1")).resolves.toBeNull();
		await expect(repo.linkFederatedIdentity?.("u1", LINK)).resolves.toEqual({
			ok: false,
			reason: "refused",
		});
		await expect(repo.findSubjectByFederatedIdentity?.(IDENTITY)).rejects.toThrow(
			`HttpUserRepository: identity lookup at ${origin}/lookup answered HTTP 401`,
		);
	};

	it.each(calls)(
		"%s: a 401 with a Bearer challenge is an outage that names the refused credential, never the token or the Store's words",
		async (_name, path, call) => {
			// Read as "no such user", a token the Store does not accept — a typo,
			// a half-finished rotation — would fail every login as a wrong
			// password and every link as a policy refusal, with nothing logged.
			const origin = await refusingStore([INVALID_TOKEN]);
			const repo = new HttpUserRepository({ ...urls(origin), bearerToken: TOKEN, timeout: 5000 });

			const outcome = await Promise.resolve(call(repo)).then(
				(value) => ({ resolved: value }),
				(error: unknown) => ({ rejected: error }),
			);

			expect(outcome).toHaveProperty("rejected");
			const error = (outcome as { rejected: unknown }).rejected;
			expect(error).toBeInstanceOf(Error);
			expect((error as Error).message).toContain(`${origin}${path}`);
			expect((error as Error).message).toMatch(/refused this deployment's credential/);
			expect((error as Error).message).toMatch(/CLIENT_USER_BEARER_TOKEN/);
			expect(surfaced(error)).not.toContain(TOKEN);
			expect(surfaced(error)).not.toContain("who are you");
		},
	);

	it("a 401 without a Bearer challenge keeps its wire meaning, with a token configured or not", async () => {
		for (const challenges of [[], ['Basic realm="store"']]) {
			const origin = await refusingStore(challenges);
			await expectWireMeaningOf401(
				new HttpUserRepository({ ...urls(origin), bearerToken: TOKEN, timeout: 5000 }),
				origin,
			);
			await expectWireMeaningOf401(
				new HttpUserRepository({ ...urls(origin), timeout: 5000 }),
				origin,
			);
		}
	});

	it("a Bearer challenge changes nothing when no token was sent — a Store whose stack challenges every 401 is unaffected", async () => {
		const origin = await refusingStore([INVALID_TOKEN]);
		await expectWireMeaningOf401(
			new HttpUserRepository({ ...urls(origin), timeout: 5000 }),
			origin,
		);
	});

	it("finds the Bearer challenge in any case, among others and on its own header line — and not inside another's parameter", async () => {
		const bearer = [
			["Bearer"],
			['bearer realm="store"'],
			[`Basic realm="store", ${INVALID_TOKEN}`],
			['Basic realm="store"', INVALID_TOKEN],
			["Negotiate, BEARER"],
		];
		const notBearer = [
			['Basic realm="Bearer"'],
			['Basic realm="store, Bearer error=x"'],
			["Bearerish"],
			["Basic bearer=x"],
			['DPoP algs="ES256"'],
		];

		const outcomes: unknown[] = [];
		for (const challenges of [...bearer, ...notBearer]) {
			const origin = await refusingStore(challenges);
			const repo = new HttpUserRepository({ ...urls(origin), bearerToken: TOKEN, timeout: 5000 });
			outcomes.push(
				await repo.authenticate("alice", "pass").then(
					(user) => ({ challenges, user }),
					(error: unknown) => ({ challenges, rejected: (error as Error).message }),
				),
			);
		}

		expect(outcomes).toEqual([
			...bearer.map((challenges) => ({
				challenges,
				rejected: expect.stringMatching(/refused this deployment's credential/),
			})),
			...notBearer.map((challenges) => ({ challenges, user: null })),
		]);
	});
});

describe("from config: the http builder", () => {
	const build = async (over: Record<string, unknown>) => {
		const userFactory = createAdapterFactory<UserRepository>("UserRepository");
		registerBuiltinAdapters({ userFactory });
		return userFactory.create({ type: "http", timeout: 5000, ...over });
	};

	it("forwards bearerToken, so every request carries it", async () => {
		const { origin, heard } = await recordingStore();
		const repo = await build({ ...urls(origin), bearerToken: TOKEN });

		for (const [, , call] of calls) await call(repo);

		expect(heard.map((h) => h.authorization)).toEqual(Array(calls.length).fill(`Bearer ${TOKEN}`));
	});

	it("sends no Authorization header when the key is absent", async () => {
		const { origin, heard } = await recordingStore();
		const repo = await build(urls(origin));

		for (const [, , call] of calls) await call(repo);

		expect(heard.map((h) => h.authorization)).toEqual(Array(calls.length).fill(undefined));
	});

	it("refuses a set bearerToken it cannot use rather than dropping it", async () => {
		// Dropped, a misconfigured token would be a deployment that believes its
		// Store calls authenticated and sends them bare.
		const base = urls("https://users.example.com");
		await expect(build({ ...base, bearerToken: 42 })).rejects.toThrow(/bearerToken/);
		await expect(build({ ...base, bearerToken: "" })).rejects.toThrow(/bearerToken/);
		await expect(build({ ...base, bearerToken: "too-short" })).rejects.toThrow(/bearerToken/);
	});
});
