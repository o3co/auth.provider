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
 * #556 — the server `request(app)` starts listens on the address supertest
 * dials, in this project's own test run.
 *
 * Unpatched, supertest starts its server with `app.listen(0)` — the
 * dual-stack wildcard `[::]:P` — and sends the request to `127.0.0.1:P`. On
 * macOS the kernel can hand out a `P` another process already holds as
 * `127.0.0.1:P`; the request then reaches that process, and if it never
 * answers the test hangs until its timeout. `vitest.supertest-loopback.mts`
 * (wired in through `setupFiles` in `vitest.config.mts`) binds the server to
 * `127.0.0.1` instead. These tests fail if that wiring is lost.
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

/**
 * An app whose `GET /hold/:name` waits in its handler until the test releases
 * that name, so a test decides the order in which requests finish.
 * `inFlight` holds the names whose handlers have not answered yet.
 */
function holdingApp() {
	const gates = new Map<
		string,
		{ arrived: PromiseWithResolvers<void>; released: PromiseWithResolvers<void> }
	>();
	const gate = (name: string) => {
		let found = gates.get(name);
		if (!found) {
			found = { arrived: Promise.withResolvers(), released: Promise.withResolvers() };
			gates.set(name, found);
		}
		return found;
	};
	const inFlight = new Set<string>();
	const app = express();
	app.get("/hold/:name", async (req, res) => {
		const { name } = req.params;
		inFlight.add(name);
		gate(name).arrived.resolve();
		await gate(name).released.promise;
		inFlight.delete(name);
		res.status(200).send(name);
	});
	return {
		app,
		inFlight,
		arrived: (name: string) => gate(name).arrived.promise,
		release: (name: string) => gate(name).released.resolve(),
		releaseAll: () => {
			for (const { released } of gates.values()) released.resolve();
		},
	};
}

/**
 * Records, for every `close` of `server`, which held requests it was still
 * serving. A close that comes too early releases them all, so the test
 * finishes and reports it instead of waiting on a close that waits on them.
 */
function recordCloses(server: http.Server, held: ReturnType<typeof holdingApp>): string[][] {
	const closes: string[][] = [];
	const close = server.close.bind(server);
	server.close = ((callback?: (err?: Error) => void) => {
		closes.push([...held.inFlight]);
		held.releaseAll();
		return close(callback);
	}) as typeof server.close;
	return closes;
}

describe("#556 — supertest's own server listens on the loopback address it dials", () => {
	it("binds 127.0.0.1, not the dual-stack wildcard", async () => {
		const server = http.createServer(helloApp());
		const bound = boundAddress(server);

		const res = await request(server).get("/hello");

		expect(res.status).toBe(200);
		expect(await bound).toMatchObject({ address: "127.0.0.1", family: "IPv4" });
		// supertest still closes the server it started.
		expect(server.listening).toBe(false);
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
		const agent = request.agent(helloApp());

		const responses = await Promise.all([agent.get("/hello"), agent.get("/hello")]);

		expect(responses.map((res) => res.status)).toEqual([200, 200]);
	});

	it("closes an agent's one server after the last request sent over it, not the first (#703)", async () => {
		// The request built first is the one whose call bound the server. Closing
		// the server when that one finishes — what supertest 7.2 did, and this
		// guard with it — resets the connection of a request still on its way:
		// ECONNRESET on Node 26.
		const held = holdingApp();
		const server = http.createServer(held.app);
		const closes = recordCloses(server, held);
		const agent = request.agent(server);

		const first = agent.get("/hold/first");
		const second = agent.get("/hold/second");
		const both = Promise.all([first, second]);
		await Promise.all([held.arrived("first"), held.arrived("second")]);
		held.release("first");
		await first;
		held.release("second");

		expect((await both).map((res) => res.text)).toEqual(["first", "second"]);
		expect(closes).toEqual([[]]);
		expect(server.listening).toBe(false);
	});

	it("keeps it open for a request sent while the server is already serving another (#703)", async () => {
		const held = holdingApp();
		const server = http.createServer(held.app);
		const closes = recordCloses(server, held);
		const agent = request.agent(server);

		// A Test is sent when it is first awaited or `then`ed; the identity
		// `then` sends each one here, before the test waits for its arrival.
		const first = agent.get("/hold/first").then((res) => res);
		await held.arrived("first");
		const late = agent.get("/hold/late").then((res) => res);
		await held.arrived("late");
		held.release("first");
		await first;
		held.release("late");

		expect((await late).text).toBe("late");
		expect(closes).toEqual([[]]);
		expect(server.listening).toBe(false);
	});

	it("binds again for a request built before the server was closed, and sent after (#703)", async () => {
		const agent = request.agent(helloApp());

		const first = agent.get("/hello");
		const second = agent.get("/hello");

		expect((await first).status).toBe(200);
		expect((await second).status).toBe(200);
	});

	it("serves a request built on a bind that failed, once another request has bound the server again (#703)", async () => {
		// The first `listen` lands on a port another socket holds; the bind
		// fails, and the request built on it is not sent until a later request
		// has bound the server on a free port. It joins that bind rather than
		// failing with the error of the one it was built on.
		const held: net.Socket[] = [];
		const squatter = net.createServer((socket) => {
			held.push(socket);
		});
		await new Promise<void>((resolve) => squatter.listen(0, "127.0.0.1", resolve));
		const { port } = squatter.address() as AddressInfo;

		const server = http.createServer(helloApp());
		const listen = server.listen.bind(server) as (...args: unknown[]) => net.Server;
		let steered = false;
		(server as { listen: (...args: unknown[]) => net.Server }).listen = (requested, ...rest) => {
			if (steered) return listen(requested, ...rest);
			steered = true;
			return listen(port, ...rest);
		};

		try {
			const failed = new Promise<void>((resolve) => server.once("error", () => resolve()));
			const builtOnTheFailedBind = request(server).get("/hello");
			await failed;
			expect((await request(server).get("/hello")).status).toBe(200);
			expect((await builtOnTheFailedBind).status).toBe(200);
			expect(server.listening).toBe(false);
		} finally {
			for (const socket of held) socket.destroy();
			squatter.close();
		}
	}, 5_000);

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
			await expect(request(server).get("/hello")).rejects.toMatchObject({
				code: "EADDRINUSE",
			});
		} finally {
			for (const socket of held) socket.destroy();
			squatter.close();
		}
	}, 5_000);
});
