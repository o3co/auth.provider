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
 * The identity lookup's transport, against a real `node:http` server (#613).
 *
 * Its own file, without msw: what is being watched here is what the client
 * does to the connection, and an interceptor that hands back a re-wrapped
 * `Response` puts itself between the client's `cancel()` and the socket.
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

let httpServer: Server | undefined;
afterEach(async () => {
	if (httpServer !== undefined) {
		httpServer.closeAllConnections();
		await new Promise<void>((resolve) => httpServer?.close(() => resolve()));
		httpServer = undefined;
	}
});

const serve = async (handler: Parameters<typeof createServer>[1]): Promise<string> => {
	httpServer = createServer(handler);
	await new Promise<void>((resolve) => httpServer?.listen(0, "127.0.0.1", resolve));
	const { port } = httpServer.address() as { port: number };
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
