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
 * The Store client's transport, against real `node:http` servers: what the
 * identity lookup does to a connection it refuses (#613), and where each of
 * the four requests is allowed to go — the URL it was configured with, and
 * nowhere a redirect points.
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

describe("where a request goes: only to the configured URL", () => {
	// Were a redirect followed, a `307` or `308` would send the same POST, body
	// and all, to the `Location` — which no https-or-loopback check has seen —
	// and a `301`/`302`/`303` would send a GET there; either way the answer
	// from there would be taken as the user, the link or the lookup's answer.
	// So a Store that answers with a redirect is answered as any other
	// unexpected status, and nothing is sent anywhere but the checked URL.
	const REDIRECTS = [307, 308, 301, 302, 303] as const;
	const LINK = {
		provider: "apple",
		sub: "a1",
		token: "apple:a1",
		claims: { email: "a@example.com", emailVerified: true },
	};
	/** How `post` reports a status it has no reading for. */
	const unexpected = (status: number, url: string) =>
		`Unexpected HTTP status ${status} from ${url}`;
	const calls = [
		[
			"authenticate",
			"/authenticate",
			(r: HttpUserRepository) => r.authenticate("alice@example.com", "correct-pass"),
			unexpected,
		],
		[
			"authenticateByToken",
			"/authenticate/token",
			(r: HttpUserRepository) => r.authenticateByToken("apple:a1"),
			unexpected,
		],
		[
			"linkFederatedIdentity",
			"/link",
			(r: HttpUserRepository) => r.linkFederatedIdentity?.("user-1", LINK),
			unexpected,
		],
		[
			"findSubjectByFederatedIdentity",
			"/lookup",
			(r: HttpUserRepository) => r.findSubjectByFederatedIdentity?.(IDENTITY),
			(status: number, url: string) =>
				`HttpUserRepository: identity lookup at ${url} answered HTTP ${status}`,
		],
	] as const;

	it.each(calls)(
		"%s: a redirect is a failure, and no redirect target hears anything",
		async (_name, path, call, failure) => {
			// Whatever reaches a `Location` is recorded and answered with a body
			// every one of the four would accept — a `User` that is also a lookup
			// answer — so a client that followed would also take its word.
			const heard: string[] = [];
			const record: Parameters<typeof createServer>[1] = (req, res) => {
				let body = "";
				req.setEncoding("utf8");
				req.on("data", (chunk: string) => {
					body += chunk;
				});
				req.on("end", () => {
					heard.push(`${req.headers.host} ${req.method} ${req.url} ${body}`);
					res.writeHead(200, { "Content-Type": "application/json" });
					res.end(
						JSON.stringify({ id: "someone-else", username: "someone-else", kind: "unlinked" }),
					);
				});
			};
			const elsewhere = await serve(record);
			let answer: { status: number; location: string | undefined } = {
				status: REDIRECTS[0],
				location: undefined,
			};
			const store = await serve((req, res) => {
				if (req.url === "/steal") {
					record(req, res);
					return;
				}
				req.resume();
				res.writeHead(answer.status, {
					"Content-Type": "text/plain",
					...(answer.location === undefined ? {} : { Location: answer.location }),
				});
				res.end("moved");
			});
			const repo = new HttpUserRepository({
				authenticateUrl: `${store}/authenticate`,
				authenticateByTokenUrl: `${store}/authenticate/token`,
				linkFederatedIdentityUrl: `${store}/link`,
				findSubjectByFederatedIdentityUrl: `${store}/lookup`,
				federatedIdentityLookupCoverage: [{ ...REG, requiredClaims: ["tid", "oid"] }],
				timeout: 5000,
			});
			const locations = [
				["another origin", `${elsewhere}/steal`],
				["the same origin, another path", "/steal"],
				["no Location at all", undefined],
			] as const;

			const outcomes: unknown[] = [];
			const expected: unknown[] = [];
			for (const [where, location] of locations) {
				for (const status of REDIRECTS) {
					answer = { status, location };
					outcomes.push({
						where,
						status,
						...(await Promise.resolve(call(repo)).then(
							(value) => ({ resolved: value }),
							(error: unknown) => ({ rejected: (error as Error).message }),
						)),
					});
					expected.push({ where, status, rejected: failure(status, `${store}${path}`) });
				}
			}

			expect(heard).toEqual([]);
			expect(outcomes).toEqual(expected);
		},
	);
});
