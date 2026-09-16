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
 * #556 — the setup file `templates/standalone/vitest.supertest-loopback.mts`,
 * which every package loads through `WORKSPACE_TEST_SETUP`, makes the server
 * supertest starts listen on the address supertest dials.
 *
 * Unpatched, `request(app)` calls `app.listen(0)`, which binds the dual-stack
 * wildcard `[::]:P`, and then dials `127.0.0.1:P`. On macOS the kernel will
 * hand out a `P` that another process already holds as `127.0.0.1:P`, and a
 * connection to `127.0.0.1:P` goes to that more specific socket, not to the
 * test's server. When that process accepts and never answers (observed: an
 * editor helper), the request hangs until the 20 s `testTimeout` — the four
 * unrelated supertest timeouts of #556, each passing on the next run. Linux
 * refuses the conflicting bind, which is why CI never showed one.
 *
 * This file lives in one package, but it exercises the shared setup: a
 * package config that drops `WORKSPACE_TEST_SETUP` fails it.
 */

import http from "node:http";
import net, { type AddressInfo } from "node:net";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";

function helloApp() {
	const app = express();
	app.get("/hello", (_req, res) => {
		res.status(200).send("hello");
	});
	return app;
}

/** Resolves with the address `server` binds, whoever calls `listen`. */
function boundAddress(server: net.Server): Promise<AddressInfo> {
	return new Promise((resolve) => {
		server.once("listening", () => resolve(server.address() as AddressInfo));
	});
}

describe("supertest's own server listens on the loopback address it dials (#556)", () => {
	it("binds 127.0.0.1, not the dual-stack wildcard, for request(server)", async () => {
		const server = http.createServer(helloApp());
		const bound = boundAddress(server);

		const res = await request(server).get("/hello");

		expect(res.status).toBe(200);
		expect(await bound).toMatchObject({ address: "127.0.0.1", family: "IPv4" });
		expect(server.listening).toBe(false);
	});

	it("binds 127.0.0.1 for every request an agent sends", async () => {
		const server = http.createServer(helloApp());
		const agent = request.agent(server);

		for (let i = 0; i < 2; i++) {
			const bound = boundAddress(server);
			const res = await agent.get("/hello");
			expect(res.status).toBe(200);
			expect(await bound).toMatchObject({ address: "127.0.0.1" });
		}
	});

	it("rejects promptly with the request's own error when the request cannot be built", async () => {
		// Node refuses this header value (ERR_INVALID_CHAR) while supertest builds
		// the request. With the loopback bind that happens after the bind settles,
		// outside the promise the test awaits; the throw must still reject that
		// promise, as it does unpatched, and not become an unhandled rejection
		// that leaves the request hanging until the test timeout.
		const server = http.createServer(helloApp());

		await expect(request(server).get("/hello").set("x-test", "bad\nvalue")).rejects.toMatchObject({
			code: "ERR_INVALID_CHAR",
		});
		// The request never went out, so nothing would close the server it started.
		expect(server.listening).toBe(false);
	}, 5_000);

	it("hands the same error to an .end() callback", async () => {
		const server = http.createServer(helloApp());

		const err = await new Promise<unknown>((resolve) => {
			request(server)
				.get("/hello")
				.set("x-test", "bad\nvalue")
				.end((error) => resolve(error));
		});

		expect(err).toMatchObject({ code: "ERR_INVALID_CHAR" });
	}, 5_000);

	it("serves requests an agent sends together over its one server", async () => {
		// `request.agent(app)` wraps the app in a single server. Unpatched, the
		// first request's synchronous listen is visible to the second; the
		// loopback listen is not yet bound when the second request is built, and
		// must not be started twice.
		const agent = request.agent(helloApp());

		const responses = await Promise.all([agent.get("/hello"), agent.get("/hello")]);

		expect(responses.map((res) => res.status)).toEqual([200, 200]);
	});

	it("leaves a server the test already started alone", async () => {
		const server = http.createServer(helloApp());
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		try {
			const res = await request(server).get("/hello");
			expect(res.status).toBe(200);
			// supertest does not own a server it did not start, so it stays up.
			expect(server.listening).toBe(true);
		} finally {
			server.close();
		}
	});

	it("fails the request, instead of hanging on another socket, when 127.0.0.1:P is taken", async () => {
		// The collision the kernel produces by chance, produced on purpose: a
		// socket that accepts and never answers holds 127.0.0.1:P, and the
		// server supertest starts is steered onto P.
		const held: net.Socket[] = [];
		const squatter = net.createServer((socket) => {
			held.push(socket);
		});
		await new Promise<void>((resolve) => squatter.listen(0, "127.0.0.1", resolve));
		const { port } = squatter.address() as AddressInfo;

		const server = http.createServer(helloApp());
		const listen = server.listen.bind(server) as (...args: unknown[]) => net.Server;
		(server as { listen: (...args: unknown[]) => net.Server }).listen = (_port, ...rest) =>
			listen(port, ...rest);

		try {
			// Unpatched on macOS this request reaches the squatter and never
			// settles; on Linux the unpatched `app.address().port` throws. Either
			// way, what the suite needs is a prompt, named failure.
			await expect(request(server).get("/hello")).rejects.toMatchObject({
				code: "EADDRINUSE",
			});
		} finally {
			for (const socket of held) socket.destroy();
			squatter.close();
		}
	}, 5_000);
});
