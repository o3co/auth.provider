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
 * What a thrown message names of a Store URL: its origin and path, never its
 * query or fragment.
 *
 * A Store endpoint may carry a query string (`?tenant=acme` is a legitimate
 * POST target), and a deployment may put a credential there despite the
 * README's advice. Every failure `HttpUserRepository` throws names the
 * endpoint, and every caller logs what it throws (`loggableError` keeps the
 * message as `detail`), so a query in the message is a query in the log.
 *
 * Run against real `node:http` and `node:net` servers — the failures are the
 * transport's, and the messages are built from what the real `fetch` did.
 */

import { createServer, type Server } from "node:http";
import { createServer as createNetServer, type Server as NetServer, type Socket } from "node:net";
import { loggableError } from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it } from "vitest";
import { HttpUserRepository } from "#/repositories/HttpUserRepository.mjs";
import { StoreCredentialRefusedError } from "#/repositories/storeErrors.mjs";

const TOKEN = "0328d706529061d93abd6d826e09ef0f0a1e71a12af813b29e5cd2977b7dc63a";
const QUERY = "?api_key=QUERY-SECRET&tenant=acme";
const FRAGMENT = "#FRAGMENT-SECRET";

const REG = {
	provider: "entra-files",
	issuer: "https://login.microsoftonline.com/T-1/v2.0",
	clientId: "grants-client",
};
const IDENTITY = { ...REG, sub: "pairwise-B", claims: { tid: "T-1", oid: "O-B" } };

let servers: Array<Server | NetServer> = [];
/** Every raw socket a TCP server accepted: `close()` waits for them, so they are destroyed first. */
let sockets: Socket[] = [];
afterEach(async () => {
	for (const socket of sockets) socket.destroy();
	sockets = [];
	await Promise.all(
		servers.map((server) => {
			if ("closeAllConnections" in server) server.closeAllConnections();
			return new Promise<void>((resolve) => server.close(() => resolve()));
		}),
	);
	servers = [];
});

type Handler = Parameters<typeof createServer>[1];

/** An HTTP server on its own loopback port; its origin. */
const serve = async (handler: Handler): Promise<string> => {
	const server = createServer(handler);
	servers.push(server);
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
};

/** A TCP server that answers every connection with bytes that are not HTTP; its origin. */
const serveGarbage = async (): Promise<string> => {
	const server = createNetServer((socket) => {
		sockets.push(socket);
		socket.on("error", () => undefined);
		socket.end("NOT-HTTP garbage\r\n\r\n");
	});
	servers.push(server);
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
};

/** An origin nothing listens on. */
const closedOrigin = async (): Promise<string> => {
	const server = createServer();
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as { port: number };
	await new Promise<void>((resolve) => server.close(() => resolve()));
	return `http://127.0.0.1:${port}`;
};

/** A repository whose every URL carries a query and a fragment. */
const repository = (origin: string, over: { timeout?: number; maxResponseBytes?: number } = {}) =>
	new HttpUserRepository({
		authenticateUrl: `${origin}/authenticate${QUERY}${FRAGMENT}`,
		authenticateByTokenUrl: `${origin}/authenticate/token${QUERY}${FRAGMENT}`,
		findSubjectByFederatedIdentityUrl: `${origin}/lookup${QUERY}${FRAGMENT}`,
		federatedIdentityLookupCoverage: [{ ...REG, requiredClaims: ["tid", "oid"] }],
		bearerToken: TOKEN,
		timeout: over.timeout ?? 5000,
		...(over.maxResponseBytes === undefined ? {} : { maxResponseBytes: over.maxResponseBytes }),
	});

type Call = (repo: HttpUserRepository) => Promise<unknown>;
const authenticate: Call = (repo) => repo.authenticate("alice@example.com", "pw");
const lookup: Call = async (repo) => repo.findSubjectByFederatedIdentity?.(IDENTITY);

/** What an assertion needs of a thrown error: a failure prints this, not the message. */
const namedIn = async (call: Call, repo: HttpUserRepository, path: string, origin: string) => {
	const thrown = await call(repo).catch((err: unknown) => err);
	const message = thrown instanceof Error ? thrown.message : `(${typeof thrown})`;
	const detail = loggableError(thrown).detail ?? "";
	return {
		threw: thrown instanceof Error,
		namesEndpoint: message.includes(`${origin}${path}`),
		quotesQuery: /QUERY-SECRET|tenant=acme|\?api_key/.test(`${message} ${detail}`),
		quotesFragment: /FRAGMENT-SECRET/.test(`${message} ${detail}`),
	};
};
const NAMED = { threw: true, namesEndpoint: true, quotesQuery: false, quotesFragment: false };

interface Case {
	readonly label: string;
	readonly call: Call;
	readonly path: string;
	readonly origin: () => Promise<string>;
	readonly over?: { readonly timeout?: number; readonly maxResponseBytes?: number };
}

const cases: readonly Case[] = [
	{
		label: "an unexpected status",
		call: authenticate,
		path: "/authenticate",
		origin: () =>
			serve((_req, res) => {
				res.writeHead(500).end();
			}),
	},
	{
		label: "a body that is not JSON",
		call: authenticate,
		path: "/authenticate",
		origin: () =>
			serve((_req, res) => {
				res.writeHead(200, { "Content-Type": "application/json" }).end("{");
			}),
	},
	{
		label: "a body that is not a User",
		call: authenticate,
		path: "/authenticate",
		origin: () =>
			serve((_req, res) => {
				res.writeHead(200, { "Content-Type": "application/json" }).end("{}");
			}),
	},
	{
		label: "a declared length over the cap",
		call: authenticate,
		path: "/authenticate",
		origin: () =>
			serve((_req, res) => {
				res.writeHead(200, { "Content-Type": "application/json", "Content-Length": "1000" });
				res.end("x".repeat(1000));
			}),
		over: { maxResponseBytes: 64 },
	},
	{
		label: "a streamed body over the cap",
		call: authenticate,
		path: "/authenticate",
		origin: () =>
			serve((_req, res) => {
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end("x".repeat(1000));
			}),
		over: { maxResponseBytes: 64 },
	},
	{
		label: "a refused credential",
		call: authenticate,
		path: "/authenticate",
		origin: () =>
			serve((_req, res) => {
				res.writeHead(401, { "WWW-Authenticate": 'Bearer error="invalid_token"' }).end();
			}),
	},
	{
		label: "a deadline",
		call: authenticate,
		path: "/authenticate",
		origin: () => serve(() => undefined),
		over: { timeout: 100 },
	},
	{
		label: "a Store nothing listens for",
		call: authenticate,
		path: "/authenticate",
		origin: closedOrigin,
	},
	{
		label: "a connection closed before the answer",
		call: authenticate,
		path: "/authenticate",
		origin: () =>
			serve((req) => {
				req.socket.destroy();
			}),
	},
	{
		label: "an answer that is not HTTP",
		call: authenticate,
		path: "/authenticate",
		origin: serveGarbage,
	},
	{
		label: "a body that broke mid-read",
		call: authenticate,
		path: "/authenticate",
		origin: () =>
			serve((req, res) => {
				res.writeHead(200, { "Content-Type": "application/json", "Content-Length": "100" });
				res.write('{"id":');
				setTimeout(() => req.socket.destroy(), 20);
			}),
	},
	{
		label: "the lookup: an unexpected status",
		call: lookup,
		path: "/lookup",
		origin: () =>
			serve((_req, res) => {
				res.writeHead(500).end();
			}),
	},
	{
		label: "the lookup: a body that is not JSON",
		call: lookup,
		path: "/lookup",
		origin: () =>
			serve((_req, res) => {
				res.writeHead(200, { "Content-Type": "application/json" }).end("{");
			}),
	},
	{
		label: "the lookup: a body that is not an answer",
		call: lookup,
		path: "/lookup",
		origin: () =>
			serve((_req, res) => {
				res.writeHead(200, { "Content-Type": "application/json" }).end("{}");
			}),
	},
	{
		label: "the lookup: a refused credential",
		call: lookup,
		path: "/lookup",
		origin: () =>
			serve((_req, res) => {
				res.writeHead(403, { "WWW-Authenticate": 'Bearer error="insufficient_scope"' }).end();
			}),
	},
	{
		label: "the lookup: a deadline",
		call: lookup,
		path: "/lookup",
		origin: () => serve(() => undefined),
		over: { timeout: 100 },
	},
	{
		label: "the lookup: a Store nothing listens for",
		call: lookup,
		path: "/lookup",
		origin: closedOrigin,
	},
	{
		label: "the lookup: a connection closed before the answer",
		call: lookup,
		path: "/lookup",
		origin: () =>
			serve((req) => {
				req.socket.destroy();
			}),
	},
	{
		label: "the lookup: an answer that is not HTTP",
		call: lookup,
		path: "/lookup",
		origin: serveGarbage,
	},
	{
		label: "the lookup: a body that broke mid-read",
		call: lookup,
		path: "/lookup",
		origin: () =>
			serve((req, res) => {
				res.writeHead(200, { "Content-Type": "application/json", "Content-Length": "100" });
				res.write('{"kind":');
				setTimeout(() => req.socket.destroy(), 20);
			}),
	},
];

describe("HttpUserRepository — what a failure names of a Store URL", () => {
	it("accepts a Store URL with a query string, as the README documents", () => {
		expect(() => repository("https://users.example.com")).not.toThrow();
	});

	it.each(cases)(
		"names only the origin and path on $label",
		async ({ call, path, origin, over }) => {
			const base = await origin();
			expect(await namedIn(call, repository(base, over), path, base)).toEqual(NAMED);
		},
	);

	it("names only the origin and path in a refused credential built from a full URL", () => {
		const err = new StoreCredentialRefusedError(
			`https://users.example.com/authenticate${QUERY}${FRAGMENT}`,
			401,
		);
		expect(err.message).toContain("the Store at https://users.example.com/authenticate refused");
		expect(err.message).not.toMatch(/QUERY-SECRET|tenant=acme|FRAGMENT-SECRET/);
	});
});
