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
 * supertest is loaded from the package that owns the running test file (the
 * nearest `package.json` above it), so the patched class is the one that test
 * imports, whatever directory vitest was started from. A package that does
 * not declare supertest is left alone. Everything else this file cannot do —
 * no test path, a declared supertest that does not load, a supertest whose
 * internals no longer look like this — throws, so the guard is never silently
 * off.
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
 * The bind in progress per server. A second request on a server whose bind has
 * not finished (an agent's requests sent together share one server) waits on
 * the same bind instead of calling `listen` twice — and, like unpatched
 * supertest when it finds a server already listening, does not own it.
 */
const binding = new WeakMap<Server, Promise<unknown>>();

function patch(proto: TestPrototype): void {
	if (proto[PATCHED]) return;
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
			// Subscribed now, not in `end`: a listen error emitted before the test
			// sends the request must still reach it, not crash the worker as an
			// unhandled 'error' event.
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

const { testPath } = expect.getState();
if (!testPath) {
	throw new Error(
		"vitest.supertest-loopback.mts: vitest did not say which test file this setup runs for, so the #556 loopback guard cannot find supertest.",
	);
}
const proto = supertestFor(testPath);
if (proto) patch(proto);
