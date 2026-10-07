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
 * And the other direction: with a token configured, a `401` or `403`
 * carrying a `Bearer` challenge (RFC 6750 §3) is the Store refusing this
 * deployment, so every one of the four requests throws a
 * StoreCredentialRefusedError — its status as `storeStatus`, never `status`;
 * one without the challenge — or any when no token is configured — keeps the
 * meaning the wire contract gives it.
 *
 * A transport failure — a refused connection, a TLS handshake refused, an
 * https URL on a plain-HTTP port, a peer that reflects the request into a
 * status line, header or body the parser rejects, a head too large, a close
 * after a 1xx — is a StoreTransportError: a fixed message naming the endpoint
 * and what failed (not reached, closed first, malformed, not readable) and at
 * most a transport code, never the transport's own error, which quotes the
 * bytes it choked on. A timeout, whichever half stalls, is a TimeoutError.
 *
 * Without msw: what is asserted is the header that reaches the socket, and an
 * interceptor is one more thing between the two.
 */

import { createServer, type Server } from "node:http";
import { createServer as createNetServer, type Server as NetServer } from "node:net";
import { createServer as createTlsServer } from "node:tls";
import { inspect } from "node:util";
import {
	createAdapterFactory,
	type FederatedIdentityLink,
	type UserRepository,
} from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it } from "vitest";
import {
	registerBuiltinAdapters,
	StoreCredentialRefusedError,
	StoreTransportError,
} from "#/index.mjs";
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
let netServers: NetServer[] = [];
afterEach(async () => {
	await Promise.all([
		...httpServers.map((server) => {
			server.closeAllConnections();
			return new Promise<void>((resolve) => server.close(() => resolve()));
		}),
		...netServers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
	]);
	httpServers = [];
	netServers = [];
});

/** A loopback origin nothing listens on: bound, then closed. */
const closedOrigin = async (): Promise<string> => {
	const server = createServer();
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as { port: number };
	await new Promise<void>((resolve) => server.close(() => resolve()));
	return `http://127.0.0.1:${port}`;
};

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
			"a refused connection": closedOrigin,
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
	 * A Store that answers every request `status` (`401` unless given), with
	 * these `WWW-Authenticate` header lines (none when empty) and a body that
	 * says why — which nothing thrown may repeat.
	 */
	const refusingStore = (challenges: readonly string[], status: 401 | 403 = 401) =>
		serve((req, res) => {
			req.resume();
			req.on("end", () => {
				res.writeHead(status, {
					"Content-Type": "application/json",
					...(challenges.length === 0 ? {} : { "WWW-Authenticate": [...challenges] }),
				});
				res.end(JSON.stringify({ error: "invalid_token", error_description: "who are you" }));
			});
		});

	const INVALID_TOKEN = 'Bearer error="invalid_token", error_description="who are you"';
	/** RFC 6750 §3.1's other refusal of the token itself: valid, and not enough. */
	const INSUFFICIENT_SCOPE = 'Bearer error="insufficient_scope", error_description="who are you"';

	/**
	 * What the four answer a `401` or `403` that is not a refused credential:
	 * the wire contract, unchanged.
	 */
	const expectWireMeaningOf = async (
		status: 401 | 403,
		repo: HttpUserRepository,
		origin: string,
	) => {
		await expect(repo.authenticate("alice", "pass")).resolves.toBeNull();
		await expect(repo.authenticateByToken("apple:a1")).resolves.toBeNull();
		await expect(repo.linkFederatedIdentity?.("u1", LINK)).resolves.toEqual({
			ok: false,
			reason: "refused",
		});
		await expect(repo.findSubjectByFederatedIdentity?.(IDENTITY)).rejects.toThrow(
			`HttpUserRepository: identity lookup at ${origin}/lookup answered HTTP ${status}`,
		);
	};

	it.each(calls)(
		"%s: a 401 or a 403 with a Bearer challenge is an outage that names the refused credential, never the token or the Store's words",
		async (_name, path, call) => {
			// Read as "no such user", a token the Store does not accept — a typo,
			// a half-finished rotation, a token without the rights the Store
			// wants — would fail every login as a wrong password and every link
			// as a policy refusal, with nothing logged.
			for (const [status, challenge] of [
				[401, INVALID_TOKEN],
				[403, INSUFFICIENT_SCOPE],
			] as const) {
				const origin = await refusingStore([challenge], status);
				const repo = new HttpUserRepository({
					...urls(origin),
					bearerToken: TOKEN,
					timeout: 5000,
				});

				const outcome = await Promise.resolve(call(repo)).then(
					(value) => ({ resolved: value }),
					(error: unknown) => ({ rejected: error }),
				);

				expect(outcome, `HTTP ${status}`).toHaveProperty("rejected");
				const error = (outcome as { rejected: unknown }).rejected;
				// A class of its own, so that a line that projects the error — the
				// grants callback's federation_grant_callback_unavailable — says
				// what happened by its name.
				expect(error).toBeInstanceOf(StoreCredentialRefusedError);
				expect((error as Error).name).toBe("StoreCredentialRefusedError");
				// Not `status`: Express and http-errors read that as the status to
				// answer with, and a 401 here would reach a browser as its own.
				expect((error as StoreCredentialRefusedError).storeStatus).toBe(status);
				expect("status" in (error as object)).toBe(false);
				expect((error as Error).message).toContain(`${origin}${path}`);
				expect((error as Error).message).toContain(`HTTP ${status} with a Bearer challenge`);
				expect((error as Error).message).toMatch(/refused this deployment's credential/);
				expect((error as Error).message).toMatch(/CLIENT_USER_BEARER_TOKEN/);
				expect(surfaced(error)).not.toContain(TOKEN);
				expect(surfaced(error)).not.toContain("who are you");
			}
		},
	);

	it("a 401 or a 403 without a Bearer challenge keeps its wire meaning, with a token configured or not", async () => {
		for (const status of [401, 403] as const) {
			for (const challenges of [[], ['Basic realm="store"']]) {
				const origin = await refusingStore(challenges, status);
				await expectWireMeaningOf(
					status,
					new HttpUserRepository({ ...urls(origin), bearerToken: TOKEN, timeout: 5000 }),
					origin,
				);
				await expectWireMeaningOf(
					status,
					new HttpUserRepository({ ...urls(origin), timeout: 5000 }),
					origin,
				);
			}
		}
	});

	it("a Bearer challenge changes nothing when no token was sent — a Store whose stack challenges every refusal is unaffected", async () => {
		for (const [status, challenge] of [
			[401, INVALID_TOKEN],
			[403, INSUFFICIENT_SCOPE],
		] as const) {
			const origin = await refusingStore([challenge], status);
			await expectWireMeaningOf(
				status,
				new HttpUserRepository({ ...urls(origin), timeout: 5000 }),
				origin,
			);
		}
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

/** The message a StoreTransportError carries for `reason`, on the lookup or one of the other three. */
const transportMessage = (lookup: boolean, url: string, reason: string, code: string): string => {
	switch (reason) {
		case "unreachable":
			return `HttpUserRepository: ${lookup ? `identity lookup at ${url}` : `request to ${url}`} could not be reached (${code})`;
		case "connection_closed":
			return lookup
				? `HttpUserRepository: identity lookup at ${url}: the connection closed before a complete response arrived (${code})`
				: `HttpUserRepository: the connection to ${url} closed before a complete response arrived (${code})`;
		case "malformed_response":
			return `HttpUserRepository: ${lookup ? `identity lookup at ${url}` : `the Store at ${url}`} answered with a malformed HTTP response (${code})`;
		default:
			throw new Error(`no message for ${reason}`);
	}
};

describe("a transport failure carries nothing the request carried", () => {
	/**
	 * A peer that answers by reflecting the request's `Authorization` into a
	 * response the HTTP parser rejects — a broken proxy, a debugging echo —
	 * where the transport's own error quotes the bytes it choked on.
	 */
	const reflecting = async (answer: (authorization: string) => string): Promise<string> => {
		const server = createNetServer((socket) => {
			// The client gives up on some answers mid-write (a head over the
			// size limit); the reset that follows is the point, not a failure.
			socket.on("error", () => {});
			let head = "";
			socket.on("data", (chunk: Buffer) => {
				head += chunk.toString("latin1");
				if (!head.includes("\r\n\r\n")) return;
				const authorization = /\r\nauthorization: ([^\r]*)/i.exec(head)?.[1] ?? "";
				socket.end(answer(authorization), "latin1");
			});
		});
		netServers.push(server);
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		const { port } = server.address() as { port: number };
		return `http://127.0.0.1:${port}`;
	};

	const REFLECTIONS = {
		"the status line": (auth: string) => `HTTP/1.1 ${auth} nope\r\n\r\n`,
		"a header line": (auth: string) =>
			`HTTP/1.1 401 Unauthorized\r\nBad Header Line ${auth}\r\n\r\n`,
		"a chunked body": (auth: string) =>
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" +
			`ZZ ${auth}\r\n`,
	} as const;

	it.each(calls)(
		"%s: a peer that reflects the token into a malformed response surfaces none of it — a StoreTransportError that says what failed, with no cause",
		async (name, path, call) => {
			// fetch rejects with `TypeError: fetch failed` whose cause, an
			// HTTPParserError, carries the offending bytes as `data`; a body that
			// breaks mid-read does the same through the stream. A logger that
			// inspects the error — core's console logger does — prints it.
			// What is thrown instead says which of the three it was: a status
			// line or header the parser rejects is a Store that was reached and
			// answered with a malformed response; a body that breaks is an
			// answer that could not be read.
			const lookup = name === "findSubjectByFederatedIdentity";
			const seen: Record<string, unknown> = {};
			const expected: Record<string, unknown> = {};
			for (const [where, answer] of Object.entries(REFLECTIONS)) {
				const origin = await reflecting(answer);
				const repo = new HttpUserRepository({
					...urls(origin),
					bearerToken: TOKEN,
					timeout: 5000,
				});
				const error = await Promise.resolve(call(repo)).then(
					() => undefined,
					(thrown: unknown) => thrown,
				);
				const url = `${origin}${path}`;
				seen[where] = {
					class: error instanceof StoreTransportError,
					name: (error as Error | undefined)?.name,
					reason: (error as { reason?: unknown } | undefined)?.reason,
					message: (error as Error | undefined)?.message,
					cause: (error as { cause?: unknown } | undefined)?.cause,
					carriesTheToken: surfaced(error).includes(TOKEN),
				};
				const unreadable = where === "a chunked body";
				expected[where] = {
					class: true,
					name: "StoreTransportError",
					reason: unreadable ? "unreadable" : "malformed_response",
					message: unreadable
						? lookup
							? `HttpUserRepository: identity lookup at ${url} could not be read`
							: `HttpUserRepository: response from ${url} could not be read`
						: lookup
							? `HttpUserRepository: identity lookup at ${url} answered with a malformed HTTP response`
							: `HttpUserRepository: the Store at ${url} answered with a malformed HTTP response`,
					cause: undefined,
					carriesTheToken: false,
				};
			}
			expect(seen).toEqual(expected);
		},
	);

	it.each(calls)(
		"%s: a timeout is a TimeoutError whether the headers or the body stall, so a reporter that reads names says timeout",
		async (_name, path, call) => {
			// A caller that reads an error's `name` — federation-grants' outage
			// classification, a projected log line — tells a timeout by it; the
			// identity lookup's timeout was already a TimeoutError and the other
			// three were plain Errors.
			const stalls = {
				"the headers": () =>
					serve((req) => {
						req.resume();
					}),
				"the body": () =>
					serve((req, res) => {
						req.resume();
						req.on("end", () => {
							res.writeHead(200, { "Content-Type": "application/json" });
							res.write('{"id":"user-1",');
							// ...and never ends.
						});
					}),
			};
			const seen: Record<string, unknown> = {};
			for (const [where, origin] of Object.entries(stalls)) {
				const base = await origin();
				const repo = new HttpUserRepository({ ...urls(base), bearerToken: TOKEN, timeout: 100 });
				const error = await Promise.resolve(call(repo)).then(
					() => undefined,
					(thrown: unknown) => thrown as Error,
				);
				seen[where] = {
					name: error?.name,
					message: error?.message,
					cause: error?.cause,
				};
			}
			const expected = {
				name: "TimeoutError",
				message: `HttpUserRepository: request to ${"<origin>"}${path} timed out after 100ms`,
				cause: undefined,
			};
			expect(
				Object.fromEntries(
					Object.entries(seen).map(([where, value]) => [
						where,
						{
							...(value as typeof expected),
							message: (value as typeof expected).message?.replace(
								/http:\/\/127\.0\.0\.1:\d+/,
								"<origin>",
							),
						},
					]),
				),
			).toEqual({ "the headers": expected, "the body": expected });
		},
	);

	it("names a transport code an operator can act on — and nothing else of the failure", async () => {
		const origin = await closedOrigin();
		const repo = new HttpUserRepository({ ...urls(origin), bearerToken: TOKEN, timeout: 5000 });
		for (const call of [
			() => repo.authenticate("alice", "pass"),
			() => repo.findSubjectByFederatedIdentity?.(IDENTITY),
		]) {
			const error = await Promise.resolve(call()).then(
				() => undefined,
				(thrown: unknown) => thrown as Error & { code?: unknown; reason?: unknown },
			);
			expect(error).toBeInstanceOf(StoreTransportError);
			expect(error?.reason).toBe("unreachable");
			expect(error?.message).toMatch(/could not be reached \(ECONNREFUSED\)$/);
			expect(error?.code).toBe("ECONNREFUSED");
			expect(error?.cause).toBeUndefined();
			expect(error !== undefined && "status" in error).toBe(false);
		}
	});

	it("names the TLS failure of an https URL that points at a port speaking plain HTTP", async () => {
		// The shape of a Store URL written https:// for a service that serves
		// http — the transport says ERR_SSL_WRONG_VERSION_NUMBER, and that is
		// the one word an operator needs.
		const plain = await serve((req, res) => {
			req.resume();
			res.end("{}");
		});
		const origin = plain.replace("http://", "https://");
		const repo = new HttpUserRepository({ ...urls(origin), bearerToken: TOKEN, timeout: 5000 });
		const error = await repo.authenticate("alice", "pass").then(
			() => undefined,
			(thrown: unknown) => thrown as Error & { code?: unknown; reason?: unknown },
		);
		expect(error).toBeInstanceOf(StoreTransportError);
		expect(error?.reason).toBe("unreachable");
		expect(error?.message).toBe(
			`HttpUserRepository: request to ${origin}/authenticate could not be reached (ERR_SSL_WRONG_VERSION_NUMBER)`,
		);
		expect(error?.code).toBe("ERR_SSL_WRONG_VERSION_NUMBER");
	});

	it("names a TLS 1.2 handshake the Store refused — the shape of mutual TLS, or no shared cipher", async () => {
		// OpenSSL 3 reports it as ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE, with
		// a slash. A TLS 1.2 server that offers only PSK ciphers refuses this
		// client's hello the same way, and needs no certificate to do it.
		const server = createTlsServer({
			ciphers: "PSK",
			maxVersion: "TLSv1.2",
			pskCallback: () => Buffer.alloc(32, 1),
		});
		server.on("tlsClientError", () => {});
		netServers.push(server);
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		const { port } = server.address() as { port: number };
		const origin = `https://127.0.0.1:${port}`;
		const repo = new HttpUserRepository({ ...urls(origin), bearerToken: TOKEN, timeout: 5000 });
		const error = await repo.authenticate("alice", "pass").then(
			() => undefined,
			(thrown: unknown) => thrown as Error & { code?: unknown; reason?: unknown },
		);
		expect(error).toBeInstanceOf(StoreTransportError);
		expect(error?.reason).toBe("unreachable");
		expect(error?.message).toBe(
			`HttpUserRepository: request to ${origin}/authenticate could not be reached (ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE)`,
		);
		expect(error?.code).toBe("ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE");
	});

	it.each(calls)(
		"%s: a head the transport cannot take is malformed_response; a connection that closes before a complete response is connection_closed — neither is the network",
		async (name, path, call) => {
			// A head too large to take reached a Store that sent bytes that are
			// not a usable head: the answer is the Store's, or a proxy's. A close —
			// after an interim 1xx, mid-head, or before any byte — says only that
			// the connection closed first: the transport cannot tell who closed
			// it or why, so the reason names no more than that. Neither is "could
			// not be reached", which would send an operator to the network.
			const lookup = name === "findSubjectByFederatedIdentity";
			const ANSWERS = {
				"a head over the size limit": [
					`HTTP/1.1 200 OK\r\nX-Big: ${"a".repeat(70_000)}\r\n\r\n`,
					"malformed_response",
					"UND_ERR_HEADERS_OVERFLOW",
				],
				"an interim 1xx, then a close": [
					"HTTP/1.1 100 Continue\r\n\r\n",
					"connection_closed",
					"UND_ERR_SOCKET",
				],
				"a head cut off": ["HTTP/1.1 200 OK\r\nContent-Len", "connection_closed", "UND_ERR_SOCKET"],
				"a close before any byte": ["", "connection_closed", "UND_ERR_SOCKET"],
			} as const;
			const seen: Record<string, unknown> = {};
			const expected: Record<string, unknown> = {};
			for (const [what, [answer, reason, code]] of Object.entries(ANSWERS)) {
				const origin = await reflecting(() => answer);
				const repo = new HttpUserRepository({
					...urls(origin),
					bearerToken: TOKEN,
					timeout: 5000,
				});
				const error = await Promise.resolve(call(repo)).then(
					() => undefined,
					(thrown: unknown) => thrown as Error & { code?: unknown; reason?: unknown },
				);
				seen[what] = {
					class: error instanceof StoreTransportError,
					reason: error?.reason,
					message: error?.message,
					code: error?.code,
				};
				expected[what] = {
					class: true,
					reason,
					message: transportMessage(lookup, `${origin}${path}`, reason, code),
					code,
				};
			}
			expect(seen).toEqual(expected);
		},
	);

	it.each(calls)(
		"%s: a pooled keep-alive connection the Store closes between requests is connection_closed — not a malformed answer",
		async (name, path, call) => {
			// fetch keeps the connection a completed exchange used and sends the
			// next request on it. A Store, a proxy or an idle timeout that closes
			// it in between makes that request fail with "other side closed" on a
			// socket that has read the whole of the first answer — bytes read,
			// and nothing malformed about any of them.
			const lookup = name === "findSubjectByFederatedIdentity";
			const ports: (number | undefined)[] = [];
			let requests = 0;
			const origin = await serve((req, res) => {
				requests += 1;
				ports.push(req.socket.remotePort);
				const first = requests === 1;
				req.resume();
				req.on("end", () => {
					if (!first) {
						req.socket.destroy();
						return;
					}
					res.writeHead(200, { "Content-Type": "application/json" });
					res.end(JSON.stringify({ id: "user-1", username: "alice", kind: "unlinked" }));
				});
			});
			const repo = new HttpUserRepository({ ...urls(origin), bearerToken: TOKEN, timeout: 5000 });

			await call(repo);
			// One turn of the event loop, as any real gap between two logins is:
			// undici returns the finished exchange's socket to its pool on a
			// later tick, and a request sent in the same tick opens a new one.
			await new Promise((resolve) => setTimeout(resolve, 10));
			const error = await Promise.resolve(call(repo)).then(
				() => undefined,
				(thrown: unknown) => thrown as Error & { code?: unknown; reason?: unknown },
			);

			// The second request rode the first one's connection.
			expect(ports).toHaveLength(2);
			expect(ports[1]).toBe(ports[0]);
			expect({
				class: error instanceof StoreTransportError,
				reason: error?.reason,
				message: error?.message,
				code: error?.code,
			}).toEqual({
				class: true,
				reason: "connection_closed",
				message: transportMessage(
					lookup,
					`${origin}${path}`,
					"connection_closed",
					"UND_ERR_SOCKET",
				),
				code: "UND_ERR_SOCKET",
			});
		},
	);
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
