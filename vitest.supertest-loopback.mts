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
 * Setup file (#556): the server supertest starts listens on the address
 * supertest dials.
 *
 * `request(app)` / `request.agent(app)` start a server with `app.listen(0)`
 * and send the request to `127.0.0.1:<port>`. A hostless `listen` binds the
 * dual-stack wildcard `[::]:P`, and on macOS (BSD `SO_REUSEADDR` semantics —
 * libuv sets it on every TCP listener) the kernel will choose a `P` that
 * another process already holds as `127.0.0.1:P`. The more specific socket
 * wins, so the test's request is delivered to that process. When it accepts
 * and never answers — the one caught was an editor helper — the request hangs
 * until the 20 s `testTimeout`: four timeouts in three packages, no code in
 * common, each green on the next run. Linux refuses the conflicting bind
 * (EADDRINUSE), which is why CI never showed one.
 *
 * Binding `127.0.0.1` explicitly removes both halves: the kernel will not
 * give out a `127.0.0.1:P` someone else holds, and against a wildcard holder
 * our specific socket is the one that receives. A specific-host `listen` is
 * asynchronous (it goes through `dns.lookup`), and supertest reads the port
 * synchronously in its constructor, so the URL is completed when the request
 * is sent (`end`, which `then` and `expect(..., fn)` go through).
 *
 * `supertest` is resolved from the package under test (the vitest worker's
 * cwd), so the patched class is the one that package's tests import. A
 * package without supertest is left alone; a supertest whose internals no
 * longer look like this fails loudly here instead of silently unguarded.
 * A server the test started itself is never touched.
 */

import { once } from "node:events";
import { createRequire } from "node:module";
import type { Server } from "node:net";
import { join } from "node:path";
import { Server as TlsServer } from "node:tls";

const LOOPBACK = "127.0.0.1";
const PATCHED = Symbol.for("o3co.auth.provider.supertest-loopback");
const PENDING = Symbol("o3co.auth.provider.supertest-loopback.pending");

/**
 * The bind in progress per server. A second request on a server whose bind has
 * not finished (an agent's requests sent together share one server) waits on
 * the same bind instead of calling `listen` twice — and, like unpatched
 * supertest when it finds a server already listening, does not own it.
 */
const binding = new WeakMap<Server, Promise<unknown>>();

type Pending = {
	readonly server: Server;
	readonly protocol: string;
	readonly path: string;
	/** Settles on `listening`, rejects on a listen `error`. */
	readonly ready: Promise<unknown>;
};

type TestInstance = {
	url: string;
	_server?: Server;
	[PENDING]?: Pending;
};

type TestPrototype = {
	serverAddress(this: TestInstance, app: Server, path: string): string;
	end(this: TestInstance, fn?: (err: unknown, res?: unknown) => void): TestInstance;
	[PATCHED]?: true;
};

const packageRequire = createRequire(join(process.cwd(), "package.json"));

const resolvesSupertest = (): boolean => {
	try {
		packageRequire.resolve("supertest");
		return true;
	} catch {
		return false;
	}
};

if (resolvesSupertest()) {
	const { Test } = packageRequire("supertest") as { Test?: { prototype: TestPrototype } };
	const proto = Test?.prototype;
	if (typeof proto?.serverAddress !== "function" || typeof proto.end !== "function") {
		throw new Error(
			"vitest.supertest-loopback.mts: supertest no longer exposes Test.prototype.serverAddress/end; " +
				"re-check the #556 loopback guard against the installed supertest before removing it.",
		);
	}

	if (!proto[PATCHED]) {
		const originalServerAddress = proto.serverAddress;
		const originalEnd = proto.end;

		proto.serverAddress = function serverAddress(app, path) {
			// Already listening: the test owns the server and chose its address.
			if (app.address()) return originalServerAddress.call(this, app, path);

			const protocol = app instanceof TlsServer ? "https" : "http";
			let ready = binding.get(app);
			if (!ready) {
				// supertest closes `_server` after the response, as it does for the
				// server it would have started itself.
				this._server = app.listen(0, LOOPBACK);
				// Subscribed now, not in `end`: a listen error emitted before the
				// test sends the request must still reach it, not crash the worker as
				// an unhandled 'error' event.
				const bound = once(app, "listening");
				binding.set(app, bound);
				bound.then(
					() => binding.delete(app),
					() => binding.delete(app),
				);
				ready = bound;
			}
			this[PENDING] = { server: app, protocol, path, ready };
			// No port yet; `end` fills it in before anything is sent.
			return `${protocol}://${LOOPBACK}${path}`;
		};

		proto.end = function end(fn) {
			const pending = this[PENDING];
			if (!pending) return originalEnd.call(this, fn);
			this[PENDING] = undefined;

			const { server, protocol, path, ready } = pending;
			ready.then(
				() => {
					const { port } = server.address() as { port: number };
					this.url = `${protocol}://${LOOPBACK}:${port}${path}`;
					originalEnd.call(this, fn);
				},
				(err: unknown) => fn?.(err),
			);
			return this;
		};

		proto[PATCHED] = true;
	}
}
