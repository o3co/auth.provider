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
 * The Store client's transport, against real `node:http` servers: the identity
 * lookup's (#613), and where every request is allowed to go.
 *
 * Its own file, without msw: what is being watched here is what the client
 * does to the connection, and an interceptor that hands back a re-wrapped
 * `Response` puts itself between the client's `cancel()` and the socket — or,
 * for a redirect, decides for itself whether to follow one.
 */

import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { HttpUserRepository } from "../HttpUserRepository.mjs";

const REG = {
	provider: "entra-files",
	issuer: "https://login.microsoftonline.com/T-1/v2.0",
	clientId: "grants-client",
};
const IDENTITY = { ...REG, sub: "pairwise-B", claims: { tid: "T-1", oid: "O-B" } };

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

const looking = (origin: string) =>
	new HttpUserRepository({
		authenticateUrl: `${origin}/authenticate`,
		authenticateByTokenUrl: `${origin}/authenticate/token`,
		findSubjectByFederatedIdentityUrl: `${origin}/lookup`,
		federatedIdentityLookupCoverage: [{ ...REG, requiredClaims: ["tid", "oid"] }],
		timeout: 5000,
	});

describe("the identity lookup on the wire (#613)", () => {
	it("releases the body of an answer it refuses, so a failing Store does not hold a socket per failure", async () => {
		// A refused answer's unfinished body is cancelled and its connection
		// closed, rather than held until garbage collection — the leak
		// `discardBody` exists for, on the path a struggling Store spends its
		// time on. The server sees that as its response closing unfinished.
		let closedUnfinished = false;
		const closed = new Promise<void>((resolve) => {
			const origin = serve((_req, res) => {
				res.on("close", () => {
					closedUnfinished = !res.writableFinished;
					resolve();
				});
				res.writeHead(500, { "Content-Type": "text/plain", "Transfer-Encoding": "chunked" });
				res.write("not for us");
				// ...and never ends.
			});
			void origin.then(async (base) => {
				await expect(looking(base).findSubjectByFederatedIdentity?.(IDENTITY)).rejects.toThrow(
					/HTTP 500/,
				);
			});
		});
		await expect(
			Promise.race([
				closed,
				new Promise<never>((_resolve, reject) =>
					setTimeout(() => reject(new Error("the connection is still open")), 2_000),
				),
			]),
		).resolves.toBeUndefined();
		expect(closedUnfinished).toBe(true);
	});
});

describe("where the credential goes: only to the configured URL", () => {
	// A `307` or `308` makes a following client send the same POST, body and
	// all, to the `Location` — which no https-or-loopback check has seen. So a
	// Store that answers with a redirect is answered as any other unexpected
	// status: nothing is sent anywhere but the URL the constructor checked.
	const REDIRECTS = [307, 308, 301, 302, 303] as const;
	const LINK = {
		provider: "apple",
		sub: "a1",
		token: "apple:a1",
		claims: { email: "a@example.com", emailVerified: true },
	};
	const calls = [
		[
			"authenticate",
			"/authenticate",
			(r: HttpUserRepository) => r.authenticate("alice@example.com", "correct-pass"),
		],
		[
			"authenticateByToken",
			"/authenticate/token",
			(r: HttpUserRepository) => r.authenticateByToken("apple:a1"),
		],
		[
			"linkFederatedIdentity",
			"/link",
			(r: HttpUserRepository) => r.linkFederatedIdentity?.("user-1", LINK),
		],
	] as const;

	it.each(calls)(
		"%s: a redirect is an unexpected status, and its Location hears nothing",
		async (_name, path, call) => {
			// The other origin records whatever reaches it, and answers as a Store
			// would — so a client that followed would also take its word for who
			// the user is.
			const heard: string[] = [];
			const elsewhere = await serve((req, res) => {
				let body = "";
				req.setEncoding("utf8");
				req.on("data", (chunk: string) => {
					body += chunk;
				});
				req.on("end", () => {
					heard.push(`${req.method} ${req.url} ${body}`);
					res.writeHead(200, { "Content-Type": "application/json" });
					res.end(JSON.stringify({ id: "someone-else", username: "someone-else" }));
				});
			});
			let status: number = REDIRECTS[0];
			const store = await serve((req, res) => {
				req.resume();
				res.writeHead(status, { Location: `${elsewhere}/steal`, "Content-Type": "text/plain" });
				res.end("moved");
			});
			const repo = new HttpUserRepository({
				authenticateUrl: `${store}/authenticate`,
				authenticateByTokenUrl: `${store}/authenticate/token`,
				linkFederatedIdentityUrl: `${store}/link`,
				timeout: 5000,
			});

			const outcomes: unknown[] = [];
			for (const redirect of REDIRECTS) {
				status = redirect;
				outcomes.push(
					await Promise.resolve(call(repo)).then(
						(value) => ({ resolved: value }),
						(error: unknown) => ({ rejected: (error as Error).message }),
					),
				);
			}

			expect(heard).toEqual([]);
			expect(outcomes).toEqual(
				REDIRECTS.map((redirect) => ({
					rejected: `Unexpected HTTP status ${redirect} from ${store}${path}`,
				})),
			);
		},
	);
});
