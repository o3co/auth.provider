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
 * vitest setup file (#556): the server supertest starts listens on the
 * address supertest dials.
 *
 * `request(app)` / `request.agent(app)` start a server with `app.listen(0)`
 * and send the request to `127.0.0.1:<port>`. A hostless `listen` binds the
 * dual-stack wildcard `[::]:P`, and on macOS (BSD `SO_REUSEADDR` semantics —
 * libuv sets it on every TCP listener) the kernel will choose a `P` that
 * another process already holds as `127.0.0.1:P`. The more specific socket
 * wins, so the test's request is delivered to that process. When it accepts
 * and never answers — an editor helper, in the case that was caught — the
 * request hangs until the test timeout, in whichever supertest test drew the
 * port, and passes on the next run. Linux refuses the conflicting bind
 * (EADDRINUSE), so CI does not show it.
 *
 * Binding `127.0.0.1` explicitly removes both halves: the kernel will not
 * give out a `127.0.0.1:P` someone else holds, and against a wildcard holder
 * our specific socket is the one that receives. A specific-host `listen` is
 * asynchronous (it goes through `dns.lookup`), and supertest reads the port
 * synchronously in its constructor, so the URL is completed when the request
 * is sent (`end`, which `then` and `expect(..., fn)` go through). A server the
 * test started itself is never touched.
 *
 * When the server supertest started is closed has changed under this file
 * once (7.3.0). 7.2 closed it after the response of the request whose call
 * bound it — for an agent, whose requests share one server, that is the first
 * request, and any other still on its way has its connection reset (#703:
 * ECONNRESET on Node 26). 7.3 counts the requests on each server it started
 * and closes the server after the last of them settles, but only for servers
 * in its own private registry, and a server this file bound is not in it. So
 * this file keeps that count itself, for either version and without them:
 * every request on a server bound here is counted from `end`, and the last to
 * settle closes the server before its own callback, the order supertest keeps.
 * A request built before that close and sent after it binds the server again.
 *
 * supertest is loaded from the package that owns the running test file (the
 * nearest `package.json` above it), so the patched class is the one that test
 * imports, whatever directory vitest was started from. A package that does
 * not declare supertest is left alone. Everything else this file cannot do —
 * no test path, a declared supertest that does not load, a supertest whose
 * internals no longer look like this — throws, so the guard is never silently
 * off. That load-time check sees only the two methods' presence; a supertest
 * that moved the `listen` out of `serverAddress` would pass it and leave the
 * guard off. The behavioural tests catch that shape of change: this
 * template's `supertest-loopback.test.mts` and its twin in the session
 * package assert the address the server actually bound.
 *
 * This file is part of the project template and ships with every scaffold.
 * The auth.provider workspace loads this same file for its packages (see
 * `WORKSPACE_TEST_SETUP` in its `vitest.shared.mts`).
 */

import { once } from "node:events";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import type { Server } from "node:net";
import { dirname, join } from "node:path";
import { Server as TlsServer } from "node:tls";
import { expect } from "vitest";

const LOOPBACK = "127.0.0.1";
const PATCHED = Symbol.for("o3co.auth.provider.supertest-loopback");
const PENDING = Symbol("o3co.auth.provider.supertest-loopback.pending");

/**
 * A server this file bound, from its `listen` until the last request on it
 * settles. It is the server's current bind for as long as `bound` maps the
 * server to it; a request built on one that no longer is — closed by its last
 * request, or failed — binds again when it is sent.
 */
type Bound = {
	/** Settles on `listening`, rejects on a listen `error`. */
	readonly ready: Promise<unknown>;
	/** The requests sent over it that have not settled. */
	pending: number;
};

type Pending = {
	readonly server: Server;
	readonly protocol: string;
	readonly path: string;
	readonly bound: Bound;
};

type TestInstance = {
	url: string;
	[PENDING]?: Pending;
};

type TestPrototype = {
	serverAddress(this: TestInstance, app: Server, path: string): string;
	end(this: TestInstance, fn?: (err: unknown, res?: unknown) => void): TestInstance;
	[PATCHED]?: true;
};

const DEPENDENCY_FIELDS = [
	"dependencies",
	"devDependencies",
	"peerDependencies",
	"optionalDependencies",
] as const;

/** The nearest `package.json` at or above `dir`. */
function owningManifest(dir: string): string | undefined {
	for (let current = dir; ; current = dirname(current)) {
		const candidate = join(current, "package.json");
		if (existsSync(candidate)) return candidate;
		if (dirname(current) === current) return undefined;
	}
}

/** supertest's `Test.prototype` as the running test file sees it, or `undefined` when its package has no supertest. */
function supertestFor(testPath: string): TestPrototype | undefined {
	const manifestPath = owningManifest(dirname(testPath));
	if (!manifestPath) {
		throw new Error(`vitest.supertest-loopback.mts: no package.json above ${testPath}.`);
	}
	const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
	const declared = DEPENDENCY_FIELDS.some(
		(field) => (manifest[field] as Record<string, unknown> | undefined)?.supertest !== undefined,
	);
	if (!declared) return undefined;

	let supertest: { Test?: { prototype: TestPrototype } };
	try {
		supertest = createRequire(manifestPath)("supertest");
	} catch (cause) {
		throw new Error(
			`vitest.supertest-loopback.mts: ${manifestPath} declares supertest, but it cannot be loaded from there; the #556 loopback guard would be off.`,
			{ cause },
		);
	}
	const proto = supertest.Test?.prototype;
	if (typeof proto?.serverAddress !== "function" || typeof proto.end !== "function") {
		throw new Error(
			"vitest.supertest-loopback.mts: supertest no longer exposes Test.prototype.serverAddress/end; " +
				"re-check the #556 loopback guard against the installed supertest before removing it.",
		);
	}
	return proto;
}

/**
 * The servers this file bound, each until the last request on it closes it.
 * A request on a server whose bind has not finished (an agent's requests sent
 * together share one server) waits on that bind instead of calling `listen`
 * twice, and one sent while the server is serving others joins their count.
 */
const bound = new WeakMap<Server, Bound>();

/** The server's bind in progress or in service, or a new one. */
function share(server: Server): Bound {
	const current = bound.get(server);
	if (current) return current;
	server.listen(0, LOOPBACK);
	// Subscribed now, not in `end`: a listen error emitted before the test
	// sends the request must still reach it, not crash the worker as an
	// unhandled 'error' event.
	const fresh: Bound = { ready: once(server, "listening"), pending: 0 };
	bound.set(server, fresh);
	// Once it has failed, the bind is left to the requests already waiting on
	// it, each of which fails with its error, and is no longer the server's:
	// the next request sent binds again, one built on the failed bind included.
	// Forgotten on the error event itself, and not on the rejection it becomes
	// — that settles a few microtasks later, and a request built in between
	// would join the failed bind.
	const failed = (): void => {
		if (bound.get(server) === fresh) bound.delete(server);
	};
	server.once("error", failed);
	fresh.ready.then(
		() => server.removeListener("error", failed),
		() => {},
	);
	return fresh;
}

/**
 * A throw from the test's own callback, raised where it cannot propagate to
 * the test: reported as an uncaught exception, which fails the run by name,
 * instead of an unhandled rejection of a promise nobody holds.
 */
function rethrowOutsideThisChain(err: unknown): void {
	process.nextTick(() => {
		throw err;
	});
}

function patch(proto: TestPrototype): void {
	if (proto[PATCHED]) return;
	const originalServerAddress = proto.serverAddress;
	const originalEnd = proto.end;

	proto.serverAddress = function serverAddress(app, path) {
		// Listening, and not bound here: the test owns the server and chose its
		// address.
		if (!bound.has(app) && app.address()) return originalServerAddress.call(this, app, path);

		// supertest is never told about this bind — neither 7.2's `_server` nor
		// 7.3's registry — so neither closes the server; the patched `end` does.
		const protocol = app instanceof TlsServer ? "https" : "http";
		this[PENDING] = { server: app, protocol, path, bound: share(app) };
		// No port yet; `end` fills it in before anything is sent.
		return `${protocol}://${LOOPBACK}${path}`;
	};

	proto.end = function end(fn) {
		const pending = this[PENDING];
		if (!pending) return originalEnd.call(this, fn);
		this[PENDING] = undefined;

		const { server, protocol, path } = pending;
		// Built on a bind that is no longer the server's — closed by its last
		// request, or failed — and sent now: bind it again, or join the bind
		// another request has made since.
		const shared = bound.get(server) === pending.bound ? pending.bound : share(server);
		shared.pending += 1;
		let called = false;
		const callback = (err: unknown, res?: unknown) => {
			called = true;
			// The last request on the server closes it, before its own callback —
			// the order supertest keeps. A bind that failed has nothing to close.
			shared.pending -= 1;
			if (shared.pending === 0 && bound.get(server) === shared) {
				bound.delete(server);
				if (server.listening) {
					server.close(() => fn?.(err, res));
					return;
				}
			}
			fn?.(err, res);
		};
		// Unpatched, whatever `end` throws while building the request (a header
		// value Node refuses, a body that will not serialize) reaches the caller
		// at once — and `then` runs `end` inside a promise executor, so the
		// awaited request rejects with it. Deferred, there is no caller left: the
		// throw, like a failed bind, is handed to the request's callback, which
		// is what rejects that promise. Nothing here may reject: a rejection of
		// this chain is one nobody awaits.
		const fail = (err: unknown) => {
			if (called) return rethrowOutsideThisChain(err);
			// The request never went out; it still leaves the count, and closes
			// the server if it was the last one on it.
			try {
				callback(err);
			} catch (thrown) {
				rethrowOutsideThisChain(thrown);
			}
		};
		shared.ready
			.then(() => {
				const { port } = server.address() as { port: number };
				this.url = `${protocol}://${LOOPBACK}:${port}${path}`;
				originalEnd.call(this, callback);
			})
			.catch(fail);
		return this;
	};

	proto[PATCHED] = true;
}

const { testPath } = expect.getState();
if (!testPath) {
	throw new Error(
		"vitest.supertest-loopback.mts: vitest did not say which test file this setup runs for, so the #556 loopback guard cannot find supertest.",
	);
}
const proto = supertestFor(testPath);
if (proto) patch(proto);
