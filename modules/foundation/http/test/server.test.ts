import { connect } from "node:net";
import { certificateForwarding } from "@mod/client-certificate";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	kernelConfig,
	type Module,
	type Runtime,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { afterEach, describe, expect, it } from "vitest";
import {
	applying,
	type HttpRequest,
	type HttpResponse,
	listening,
	type PolicyRule,
	policies,
	policy,
	type Route,
	routes,
	site,
	use,
} from "../src/contract.ts";
import http from "../src/module.ts";
import { testRequest } from "../src/testing.ts";
import { declared } from "./declared.ts";

const quiet = quietRuntime({
	clock: { now: () => 0 },
	random: { bytes: (n) => new Uint8Array(n) },
});

/** A runtime that keeps the events it warns of, its clock at `at()`. */
function warning(at: () => number = () => 0) {
	const recorded = recordingLog();
	const runtime = quietRuntime({ ...quiet, clock: { now: at }, log: recorded.log });
	const count = (event: string) =>
		recorded.lines().filter((line) => line.level === "warn" && line.event === event).length;
	return { runtime, count };
}

/** Sends raw bytes and reads the status line of the answer. */
function rawStatus(port: number, request: string): Promise<number> {
	return new Promise((resolve, reject) => {
		const socket = connect(port, "127.0.0.1", () => socket.end(request));
		let text = "";
		socket.on("data", (chunk) => {
			text += chunk.toString();
		});
		socket.on("end", () => resolve(Number(/^HTTP\/1\.1 (\d{3})/.exec(text)?.[1] ?? 0)));
		socket.on("error", reject);
	});
}

let stop: () => Promise<void> = async () => {};
afterEach(async () => {
	await stop();
	stop = async () => {};
});

/** http with these http settings and modules, on any free port. */
function boot(
	settings: Record<string, unknown> = {},
	options: { modules?: Module[]; runtime?: Runtime } = {},
) {
	return assemble({
		modules: [http, ...(options.modules ?? [])],
		config: { ...kernelConfig(), http: { port: 0, ...settings } },
		runtime: options.runtime ?? quiet,
	});
}

/** Boots and starts http with these handlers; the base URL. */
async function serveWith(handlers: Module, settings = {}, runtime = quiet) {
	const app = await boot(settings, { modules: [handlers], runtime });
	await app.start();
	stop = () => app.stop(1000);
	return `http://127.0.0.1:${app.get(listening).port()}`;
}

/** A module contributing these policy rules, then these routes. */
function handlers(list: readonly Route[], rules: readonly PolicyRule[] = []): Module {
	return defineModule({ name: "handlers" }, (m) => [
		...rules.map((rule) => m.contribute(policies).by(() => rule)),
		...list.map((route) => m.contribute(routes).by(() => declared(route))),
	]);
}

/** The refusals a boot is refused with, as [where, reason]. */
async function refusalsOf(booting: Promise<unknown>) {
	const error = await booting.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(error).toBeInstanceOf(BootRefused);
	return (error as BootRefused).refusals.map((r) => [r.where, r.reason]);
}

describe("http", () => {
	it("sends each cookie as its own Set-Cookie header, and tells the handler the source", async () => {
		let seen: HttpRequest | undefined;
		const base = await serveWith(
			handlers([
				{
					method: "GET",
					path: "/cookies",
					handle: (request) => {
						seen = request;
						return { status: 204, cookies: ["a=1; Path=/", "b=2; Path=/"] };
					},
				},
			]),
		);
		const res = await fetch(`${base}/cookies`, { headers: { "x-forwarded-for": "198.51.100.1" } });
		expect(res.headers.getSetCookie()).toEqual(["a=1; Path=/", "b=2; Path=/"]);
		expect(seen?.source).toEqual({ address: "127.0.0.1", scheme: "http", determined: true });
	});

	it("follows forwarded addresses through trusted proxies as far as proxy-hops says", async () => {
		const sources: string[] = [];
		const route = handlers([
			{
				method: "GET",
				path: "/",
				handle: (request) => {
					sources.push(request.source.address);
					return { status: 204 };
				},
			},
		]);
		const forwarded = { headers: { "x-forwarded-for": "198.51.100.1, 10.0.0.2" } };
		const trusted = ["127.0.0.1", "10.0.0.0/8"];
		await fetch(await serveWith(route, { "trusted-proxies": trusted }), forwarded);
		await stop();
		await fetch(await serveWith(route, { "trusted-proxies": trusted, "proxy-hops": 2 }), forwarded);
		expect(sources).toEqual(["10.0.0.2", "198.51.100.1"]);
	});

	it("routes by method and path and hands over a frozen request", async () => {
		let seen: HttpRequest | undefined;
		const base = await serveWith(
			handlers([
				{
					method: "GET",
					path: "/echo",
					handle: (request) => {
						seen = request;
						return { status: 200, body: { json: { a: request.query.get("a") } } };
					},
				},
			]),
		);
		const res = await fetch(`${base}/echo?a=1&a=2`);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ a: ["1", "2"] });
		expect(Object.isFrozen(seen)).toBe(true);
		for (const map of [seen?.query, seen?.form, seen?.headers] as Map<string, never>[]) {
			expect(() => map.set("a", [] as never)).toThrow(TypeError);
			expect(() => map.delete("a")).toThrow(TypeError);
			expect(() => map.clear()).toThrow(TypeError);
		}
		expect(seen?.query.get("a")).toEqual(["1", "2"]);
		expect([seen?.query.single("a"), seen?.query.repeated()]).toEqual([undefined, ["a"]]);
	});

	it("reads form bodies with repeated names and ignores other bodies", async () => {
		const forms: unknown[] = [];
		const base = await serveWith(
			handlers([
				{
					method: "POST",
					path: "/form",
					handle: (request) => {
						forms.push(Object.fromEntries(request.form));
						return { status: 204 };
					},
				},
			]),
		);
		await fetch(`${base}/form`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded; charset=utf-8" },
			body: "a=1&a=2&b=%20x",
		});
		await fetch(`${base}/form`, { method: "POST", body: JSON.stringify({ a: 1 }) });
		expect(forms).toEqual([{ a: ["1", "2"], b: [" x"] }, {}]);
	});

	it("answers 400 to a query whose percent-escapes are not UTF-8, and reads one that is", async () => {
		const seen: unknown[] = [];
		const base = await serveWith(
			handlers([
				{
					method: "GET",
					path: "/q",
					handle: (request) => {
						seen.push(Object.fromEntries(request.query));
						return { status: 204 };
					},
				},
			]),
		);
		for (const query of ["a=%C3%28", "a=%E9", "%E9=1"]) {
			const res = await fetch(`${base}/q?${query}`);
			expect([res.status, res.headers.get("cache-control"), await res.text()], query).toEqual([
				400,
				"no-store",
				"",
			]);
		}
		expect((await fetch(`${base}/q?a=%C3%A9&b=x+y&c=&d=%zz`)).status).toBe(204);
		expect(seen).toEqual([{ a: ["é"], b: ["x y"], c: [""], d: ["%zz"] }]);
	});

	it("answers 400 to a request target it cannot read as a URL, and keeps serving", async () => {
		const base = await serveWith(
			handlers([{ method: "GET", path: "/x", handle: () => ({ status: 204 }) }]),
		);
		const { port } = new URL(base);
		for (const target of ["http://[", "http://a:b", "//["]) {
			expect(
				await rawStatus(
					Number(port),
					`GET ${target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`,
				),
			).toBe(400);
		}
		expect((await fetch(`${base}/x`)).status).toBe(204);
	});

	it("answers unknown paths with 404 and wrong methods with 405", async () => {
		const base = await serveWith(
			handlers([{ method: "GET", path: "/x", handle: () => ({ status: 204 }) }]),
		);
		expect((await fetch(`${base}/nope`)).status).toBe(404);
		const wrong = await fetch(`${base}/x`, { method: "POST" });
		expect(wrong.status).toBe(405);
		expect(wrong.headers.get("allow")).toBe("GET, HEAD");
		expect(wrong.headers.get("cache-control")).toBe("no-store");
	});

	it("types a JSON answer as JSON unless its route types it", async () => {
		const base = await serveWith(
			handlers([
				{ method: "GET", path: "/json", handle: () => ({ status: 200, body: { json: {} } }) },
				{
					method: "GET",
					path: "/jwks",
					handle: () => ({
						status: 200,
						headers: { "content-type": "application/jwk-set+json" },
						body: { json: { keys: [] } },
					}),
				},
			]),
		);
		const type = async (path: string) =>
			(await fetch(`${base}${path}`)).headers.get("content-type");
		expect([await type("/json"), await type("/jwks")]).toEqual([
			"application/json",
			"application/jwk-set+json",
		]);
	});

	it("hands a handler header lines sent more than once joined with a comma", async () => {
		let seen: string | undefined;
		const base = await serveWith(
			handlers([
				{
					method: "GET",
					path: "/x",
					handle: (request) => {
						seen = request.headers.get("set-cookie");
						return { status: 204 };
					},
				},
			]),
		);
		const sent =
			"GET /x HTTP/1.1\r\nHost: x\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nConnection: close\r\n\r\n";
		expect(await rawStatus(Number(new URL(base).port), sent)).toBe(204);
		expect(seen).toBe("a=1, b=2");
	});

	it("answers 500 to a failure outside the handler's own, and keeps serving", async () => {
		const base = await serveWith(
			handlers([
				{ method: "GET", path: "/void", cors: {}, handle: () => undefined as never },
				{ method: "GET", path: "/ok", handle: () => ({ status: 204 }) },
			]),
		);
		expect((await fetch(`${base}/void`)).status).toBe(500);
		expect((await fetch(`${base}/ok`)).status).toBe(204);
	});

	it("serves a path and everything under it from a route ending in /*, exact routes first", async () => {
		const base = await serveWith(
			handlers(
				(
					[
						["GET", "/fed/*", "any"],
						["POST", "/fed/*", "posted"],
						["GET", "/fed/deep/*", "deep"],
						["GET", "/fed/fixed", "fixed"],
					] as const
				).map(([method, path, tag]) => ({
					method,
					path,
					handle: (request: HttpRequest) => ({ status: 200, body: `${tag} ${request.path}` }),
				})),
			),
		);
		const text = async (path: string, method = "GET") =>
			(await fetch(`${base}${path}`, { method })).text();
		expect(await text("/fed/google")).toBe("any /fed/google");
		expect(await text("/fed/google/callback")).toBe("any /fed/google/callback");
		expect(await text("/fed/google/callback", "POST")).toBe("posted /fed/google/callback");
		expect(await text("/fed/deep/x")).toBe("deep /fed/deep/x");
		expect(await text("/fed/fixed")).toBe("fixed /fed/fixed");
		expect((await fetch(`${base}/fed`)).status).toBe(404);
		expect((await fetch(`${base}/fedx/a`)).status).toBe(404);
		const wrong = await fetch(`${base}/fed/deep/x`, { method: "PUT" });
		expect([wrong.status, wrong.headers.get("allow")]).toEqual([405, "GET, HEAD"]);
	});

	it("answers Unavailable with a retryable 503 and other failures without detail", async () => {
		const recorded = recordingLog();
		const base = await serveWith(
			handlers([
				{
					method: "GET",
					path: "/down/*",
					handle: () => {
						throw new Unavailable("store");
					},
				},
				{
					method: "GET",
					path: "/boom",
					handle: () => {
						throw new Error("secret=xyz");
					},
				},
			]),
			{},
			quietRuntime({ ...quiet, log: recorded.log }),
		);
		const down = await fetch(`${base}/down/sent`);
		expect(down.status).toBe(503);
		expect([down.headers.get("cache-control"), down.headers.get("pragma")]).toEqual([
			"no-store",
			"no-cache",
		]);
		expect(await down.json()).toEqual({ error: "service_unavailable" });
		expect(recorded.lines().filter((line) => line.level === "warn")).toEqual([
			{ level: "warn", event: "http.unavailable", fields: { what: "store", route: "/down/*" } },
		]);
		const boom = await fetch(`${base}/boom`);
		expect(boom.status).toBe(500);
		expect(await boom.text()).not.toContain("xyz");
	});
});

describe("a route's unavailable answer", () => {
	const failing = policy("test.failing");
	const rule = applying(failing, async () => {
		throw new Unavailable("policy store");
	});
	const declared: HttpResponse = {
		status: 503,
		headers: { "cache-control": "no-store", "retry-after": "5" },
		body: { json: { error: "temporarily_unavailable" } },
	};

	/** Serves a handler and a policy throwing Unavailable, both declaring `noted`; the base URL and the lines past info. */
	async function serveDown(noted: (request: HttpRequest) => Record<string, string> | undefined) {
		const recorded = recordingLog();
		const unavailable = { response: declared, noted };
		const throwing = () => {
			throw new Unavailable("store");
		};
		const base = await serveWith(
			handlers(
				[
					{ method: "POST", path: "/handled", unavailable, handle: throwing },
					{
						method: "GET",
						path: "/guarded",
						uses: [use(failing)],
						unavailable,
						handle: () => ({ status: 204 }),
					},
				],
				[rule],
			),
			{},
			quietRuntime({ ...quiet, log: recorded.log }),
		);
		return { base, lines: () => recorded.lines().filter((line) => line.level !== "info") };
	}

	it("answers what the route declares when its handler or its policy throws Unavailable", async () => {
		const { base } = await serveDown(() => undefined);
		for (const res of [
			await fetch(`${base}/handled`, { method: "POST" }),
			await fetch(`${base}/guarded`),
		]) {
			expect([res.status, res.headers.get("retry-after"), await res.json()]).toEqual([
				503,
				"5",
				{ error: "temporarily_unavailable" },
			]);
		}
	});

	it("warns once, with what was unavailable, the declared route, and the fields the route notes", async () => {
		const seen: string[] = [];
		const { base, lines } = await serveDown((request) => {
			seen.push(request.method);
			return { grant_type: "test" };
		});
		await fetch(`${base}/handled`, { method: "POST" });
		await fetch(`${base}/guarded`);
		expect(seen).toEqual(["POST", "GET"]);
		expect(lines()).toEqual([
			{
				level: "warn",
				event: "http.unavailable",
				fields: { what: "store", route: "/handled", grant_type: "test" },
			},
			{
				level: "warn",
				event: "http.unavailable",
				fields: { what: "policy store", route: "/guarded", grant_type: "test" },
			},
		]);
	});

	it("still answers what the route declares when noting throws, logging the failure by kind only", async () => {
		const { base, lines } = await serveDown(() => {
			throw new TypeError("secret=xyz");
		});
		const res = await fetch(`${base}/handled`, { method: "POST" });
		expect([res.status, await res.json()]).toEqual([503, { error: "temporarily_unavailable" }]);
		expect(lines()).toEqual([
			{ level: "error", event: "http.failed", fields: { kind: "TypeError" } },
			{ level: "warn", event: "http.unavailable", fields: { what: "store", route: "/handled" } },
		]);
	});
});

describe("stop", () => {
	const slow = "GET /slow HTTP/1.1\r\nHost: x\r\n\r\n";

	/** A route answering only once released, saying when it is reached; and a route answering at once. */
	function gated(answered: HttpResponse = { status: 200, body: "done" }) {
		const reached = Promise.withResolvers<void>();
		const released = Promise.withResolvers<void>();
		const route = handlers([
			{
				method: "GET",
				path: "/slow",
				handle: async () => {
					reached.resolve();
					await released.promise;
					return answered;
				},
			},
			{ method: "GET", path: "/fast", handle: () => ({ status: 204 }) },
		]);
		return { route, reached: reached.promise, release: () => released.resolve() };
	}

	async function started(modules: Module[]) {
		const app = await boot({}, { modules });
		await app.start();
		stop = () => app.stop(1000);
		return { app, port: app.get(listening).port() };
	}

	/** Sends a request on its own connection; all it reads once the server closes it. */
	function exchange(port: number, request: string): Promise<string> {
		const socket = connect(port, "127.0.0.1", () => socket.write(request));
		let text = "";
		socket.on("data", (chunk) => {
			text += chunk.toString();
		});
		socket.on("error", () => {});
		return new Promise((resolve) => socket.on("close", () => resolve(text)));
	}

	/** Whether a new connection is accepted, or the error code it is refused with. */
	function connecting(port: number): Promise<string> {
		return new Promise((resolve) => {
			const socket = connect(port, "127.0.0.1", () => {
				socket.destroy();
				resolve("accepted");
			});
			socket.on("error", (error: NodeJS.ErrnoException) => resolve(error.code ?? "error"));
		});
	}

	// Stop's hooks start within microtasks, so one macrotask later the listener is closed.
	const hooksStarted = () => new Promise((resolve) => setImmediate(resolve));

	it("lets a request in flight finish, refusing new connections, and closes its connection after the answer", async () => {
		const gate = gated();
		const { app, port } = await started([gate.route]);
		const answer = exchange(port, slow);
		await gate.reached;
		const stopping = app.stop(10_000);
		await hooksStarted();
		expect(await connecting(port)).toBe("ECONNREFUSED");
		gate.release();
		const text = await answer;
		expect(text).toMatch(/^HTTP\/1\.1 200 /);
		expect(text.toLowerCase()).toContain("\r\nconnection: close\r\n");
		expect(text).toMatch(/done$/);
		await stopping;
	});

	it("answers 500 with none of an unwritable answer's headers while stopping", async () => {
		const location = "https://x.example/\r\nx: 1";
		const gate = gated({ status: 303, cookies: ["a=1"], headers: { location } });
		const { app, port } = await started([gate.route]);
		const answer = exchange(port, slow);
		await gate.reached;
		const stopping = app.stop(10_000);
		await hooksStarted();
		gate.release();
		const text = (await answer).toLowerCase();
		expect(text).toMatch(/^http\/1\.1 500 /);
		expect([text.includes("set-cookie"), text.includes("location")]).toEqual([false, false]);
		await stopping;
	});

	it("closes an idle keep-alive connection at once, so it does not hold stop up", async () => {
		const { app, port } = await started([gated().route]);
		const socket = connect(port, "127.0.0.1", () =>
			socket.write("GET /fast HTTP/1.1\r\nHost: x\r\n\r\n"),
		);
		socket.on("error", () => {});
		const closed = new Promise((resolve) => socket.on("close", resolve));
		await new Promise((resolve) => socket.once("data", resolve));
		const held = new Promise((resolve) => setTimeout(() => resolve("held"), 2000));
		expect(await Promise.race([app.stop(10_000).then(() => "stopped"), held])).toBe("stopped");
		await closed;
	});

	it("closes a connection whose answer was still being sent when stop began, once the answer is sent", async () => {
		const body = "x".repeat(16 * 1024 * 1024);
		const big = handlers([{ method: "GET", path: "/big", handle: () => ({ status: 200, body }) }]);
		const { app, port } = await started([big]);
		let length = 0;
		const socket = connect(port, "127.0.0.1", () =>
			socket.write("GET /big HTTP/1.1\r\nHost: x\r\n\r\n"),
		);
		socket.on("error", () => {});
		// The answer starts as keep-alive, then waits on a reader that does not read.
		socket.once("data", () => socket.pause());
		socket.on("data", (chunk) => {
			length += chunk.length;
		});
		const closed = new Promise((resolve) => socket.on("close", () => resolve("closed")));
		await new Promise((resolve) => setTimeout(resolve, 50));
		const stopping = app.stop(10_000);
		await hooksStarted();
		socket.resume();
		const held = new Promise((resolve) => setTimeout(() => resolve("held"), 2000));
		expect(await Promise.race([closed, held])).toBe("closed");
		expect(length).toBeGreaterThan(body.length);
		await stopping;
	});

	it("closes at the stop deadline the connections still waiting for an answer", async () => {
		const gate = gated();
		const { app, port } = await started([gate.route]);
		const answer = exchange(port, slow);
		await gate.reached;
		await app.stop(50);
		expect(await answer).toBe("");
	});

	it("closes every connection at once when stop reaches it past the deadline", async () => {
		const gate = gated();
		const held = contract<object>("test.held");
		const hanging = defineModule({ name: "hanging" }, (m) => [
			m.provide(held).by((c) => {
				c.onStop(() => new Promise(() => {}));
				return {};
			}),
		]);
		const { app, port } = await started([gate.route, hanging]);
		const answer = exchange(port, slow);
		await gate.reached;
		await app.stop(50);
		expect(await answer).toBe("");
	});
});

it("says it is reached through a proxy only when it trusts one", async () => {
	expect((await boot()).get(site).proxied).toBe(false);
	expect((await boot({ "trusted-proxies": ["10.0.0.0/8"] })).get(site).proxied).toBe(true);
});

it("states the public origin it was given, and refuses one with a path", async () => {
	const app = await boot({ "public-origin": "https://as.example" });
	expect(app.get(site).origin).toBe("https://as.example");
	expect(app.get(site).secureCookies).toBe(true);
	expect(Object.isFrozen(app.get(site))).toBe(true);
	for (const origin of ["https://as.example/x", "ws://as.example", "ftp://as.example"]) {
		await expect(boot({ "public-origin": origin }), origin).rejects.toThrow(BootRefused);
	}
});

it("refuses an empty or unparsable public origin or CORS origin at boot, never throwing on it", async () => {
	for (const origin of ["", "not a url", "https://"]) {
		await expect(boot({ "public-origin": origin }), `public ${origin}`).rejects.toThrow(
			BootRefused,
		);
		await expect(boot({ "cors-origins": [origin] }), `cors ${origin}`).rejects.toThrow(BootRefused);
	}
});

it("answers 500 for an answer whose headers cannot be written, and keeps serving", async () => {
	const base = await serveWith(
		handlers([
			{
				method: "GET",
				path: "/bad",
				handle: () => ({
					status: 303,
					headers: { location: "https://x.example/\r\nset-cookie: a=1" },
				}),
			},
			{ method: "GET", path: "/ok", handle: () => ({ status: 204 }) },
		]),
	);
	const bad = await fetch(`${base}/bad`, { redirect: "manual" });
	expect([bad.status, bad.headers.get("location"), bad.headers.getSetCookie()]).toEqual([
		500,
		null,
		[],
	]);
	expect((await fetch(`${base}/ok`)).status).toBe(204);
});

it("warns, at most once a minute, when a peer it does not trust sends forwarded headers", async () => {
	let at = 0;
	const { runtime, count } = warning(() => at);
	const base = await serveWith(
		handlers([{ method: "GET", path: "/", handle: () => ({ status: 204 }) }]),
		{},
		runtime,
	);
	await fetch(base, { headers: { "x-forwarded-for": "198.51.100.1" } });
	await fetch(base, { headers: { "x-forwarded-for": "198.51.100.2" } });
	await fetch(base);
	expect(count("http.forwarded_from_untrusted_peer")).toBe(1);
	at = 60_000;
	await fetch(base, { headers: { "x-forwarded-for": "198.51.100.3" } });
	expect(count("http.forwarded_from_untrusted_peer")).toBe(1);
	at = 60_001;
	await fetch(base, { headers: { "x-forwarded-for": "198.51.100.3" } });
	expect(count("http.forwarded_from_untrusted_peer")).toBe(2);
});

it("does not warn when a trusted proxy sends forwarded headers", async () => {
	const { runtime, count } = warning();
	const base = await serveWith(
		handlers([{ method: "GET", path: "/", handle: () => ({ status: 204 }) }]),
		{ "trusted-proxies": ["127.0.0.1"] },
		runtime,
	);
	await fetch(base, { headers: { "x-forwarded-for": "198.51.100.1" } });
	expect(count("http.forwarded_from_untrusted_peer")).toBe(0);
});

it("refuses a plain-http public origin unless it is accepted explicitly, and then says cookies cannot be secure", async () => {
	await expect(boot({ "public-origin": "http://as.example" })).rejects.toThrow(BootRefused);
	const app = await boot({ "public-origin": "http://as.example", "insecure-origin": true });
	expect(app.get(site).secureCookies).toBe(false);
});

it("refuses a port an environment variable gives empty, signed, fractional or not in decimal", async () => {
	for (const port of ["", " ", "-1", "+80", "1.5", "0x1f90", 1.5, -1, true]) {
		await expect(boot({ port }), JSON.stringify(port)).rejects.toBeInstanceOf(BootRefused);
	}
	expect((await boot({ port: "8080" })).get(listening)).toBeDefined();
});

it("refuses a key its section does not know", async () => {
	await expect(boot({ "trusted-proxy": ["127.0.0.1"] })).rejects.toThrow(BootRefused);
});

it("listens only on the address it is given", async () => {
	const base = await serveWith(handlers([]));
	const reached = await new Promise((resolve) => {
		const socket = connect(Number(new URL(base).port), "::1", () => {
			socket.destroy();
			resolve("accepted");
		});
		socket.on("error", () => resolve("refused"));
	});
	expect(reached).toBe("refused");
});

it("logs a failure by its kind only, never its message", async () => {
	const recorded = recordingLog();
	const runtime = quietRuntime({ ...quiet, log: recorded.log });
	const boom = () => {
		throw new TypeError("secret=xyz");
	};
	const base = await serveWith(
		handlers([{ method: "GET", path: "/boom", handle: boom }]),
		{},
		runtime,
	);
	expect((await fetch(`${base}/boom`)).status).toBe(500);
	expect(recorded.lines().filter((line) => line.level === "error")).toEqual([
		{ level: "error", event: "http.failed", fields: { kind: "TypeError" } },
	]);
});

it("logs a failure outside the handler's own by the route and its kind only, and answers 500", async () => {
	const recorded = recordingLog();
	const runtime = quietRuntime({ ...quiet, log: recorded.log });
	const base = await serveWith(
		handlers([{ method: "GET", path: "/void", cors: {}, handle: () => undefined as never }]),
		{},
		runtime,
	);
	expect((await fetch(`${base}/void`)).status).toBe(500);
	const logged = recorded.lines().filter((line) => line.event === "http.unexpected_failure");
	expect(logged).toEqual([
		{
			level: "warn",
			event: "http.unexpected_failure",
			fields: { route: "/void", kind: "TypeError" },
		},
	]);
});

it("states an answer's length in bytes", async () => {
	const base = await serveWith(
		handlers([{ method: "GET", path: "/x", handle: () => ({ status: 200, body: "é€" }) }]),
	);
	const head = await fetch(`${base}/x`, { method: "HEAD" });
	expect(head.headers.get("content-length")).toBe("5");
});

it("keeps serving, raising no unhandled rejection, when an answer fails after its headers are written", async () => {
	const unhandled: unknown[] = [];
	const spy = (reason: unknown) => unhandled.push(reason);
	process.on("unhandledRejection", spy);
	try {
		const base = await serveWith(
			handlers([
				// A body Node cannot send, though its length can be stated: it fails after the headers.
				{
					method: "GET",
					path: "/view",
					handle: () => ({ status: 200, body: new DataView(new ArrayBuffer(4)) as never }),
				},
				{ method: "GET", path: "/ok", handle: () => ({ status: 204 }) },
			]),
		);
		await rawStatus(
			Number(new URL(base).port),
			"GET /view HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
		);
		await new Promise((r) => setTimeout(r, 50));
		expect(unhandled).toEqual([]);
		expect((await fetch(`${base}/ok`)).status).toBe(204);
	} finally {
		process.off("unhandledRejection", spy);
	}
});

describe("route policies", () => {
	const gate = policy<{ readonly open: boolean }>("test.gate");
	const mark = policy("test.mark");
	const failing = policy("test.failing");

	it("applies the policies a route uses in order before its handler, and a policy may answer instead", async () => {
		const seen: string[] = [];
		const handled = () => {
			seen.push("handled");
			return { status: 204 };
		};
		const base = await serveWith(
			handlers(
				[
					{
						method: "GET",
						path: "/open",
						uses: [use(mark), use(gate, { open: true })],
						handle: handled,
					},
					{
						method: "GET",
						path: "/shut",
						uses: [use(gate, { open: false }), use(mark)],
						handle: handled,
					},
					{ method: "GET", path: "/failing", uses: [use(failing)], handle: handled },
				],
				[
					applying(gate, (_request, options) => {
						seen.push(`gate ${options.open}`);
						return options.open ? "pass" : { status: 403, body: { json: { error: "shut" } } };
					}),
					applying(mark, () => {
						seen.push("mark");
						return "pass";
					}),
					applying(failing, async () => {
						throw new Unavailable("test");
					}),
				],
			),
		);
		expect((await fetch(`${base}/open`)).status).toBe(204);
		expect(seen).toEqual(["mark", "gate true", "handled"]);
		seen.length = 0;
		const shut = await fetch(`${base}/shut`);
		expect([shut.status, await shut.json()]).toEqual([403, { error: "shut" }]);
		expect(seen).toEqual(["gate false"]);
		expect((await fetch(`${base}/failing`)).status).toBe(503);
	});

	it("refuses at boot a route that uses a policy no module applies, naming the route and the policy", async () => {
		const booting = serveWith(
			handlers(
				[
					// Named like a policy that has a rule, yet another value: matched by value, it has none.
					{
						method: "POST",
						path: "/lonely",
						uses: [use(policy("test.mark"))],
						handle: () => ({ status: 204 }),
					},
					{ method: "GET", path: "/alone", uses: [use(failing)], handle: () => ({ status: 204 }) },
				],
				[applying(mark, () => "pass")],
			),
		);
		expect(await refusalsOf(booting)).toEqual([
			["http.routes:POST /lonely", "uses a policy no module applies: test.mark"],
			["http.routes:GET /alone", "uses a policy no module applies: test.failing"],
		]);
	});

	it("keeps two policies of the same name from different owners apart", async () => {
		const theirs = policy("shared.name");
		const ours = policy("shared.name");
		const base = await serveWith(
			handlers(
				[
					{ method: "GET", path: "/theirs", uses: [use(theirs)], handle: () => ({ status: 204 }) },
					{ method: "GET", path: "/ours", uses: [use(ours)], handle: () => ({ status: 204 }) },
				],
				[applying(theirs, () => ({ status: 401 })), applying(ours, () => "pass")],
			),
		);
		const statuses = [(await fetch(`${base}/theirs`)).status, (await fetch(`${base}/ours`)).status];
		expect(statuses).toEqual([401, 204]);
	});

	it("makes a policy and a route's use of it frozen values", () => {
		expect([Object.isFrozen(gate), Object.isFrozen(use(gate, { open: true }))]).toEqual([
			true,
			true,
		]);
	});

	it("refuses at boot two routes taking one method and path, naming the route", async () => {
		const route: Route = { method: "GET", path: "/x", handle: () => ({ status: 204 }) };
		const twice = handlers([route, { ...route, method: "POST" }, route]);
		expect(await refusalsOf(serveWith(twice))).toEqual([
			["http.routes:GET /x", "more than one contribution for the same key"],
		]);
	});

	it("refuses at boot two rules for one policy", async () => {
		const ours = policy("shared.name");
		const twice = handlers([], [applying(ours, () => "pass"), applying(ours, () => "pass")]);
		expect(await refusalsOf(serveWith(twice))).toEqual([
			["http.policies", "more than one rule for a policy: shared.name"],
		]);
	});
});

describe("the client's certificate", () => {
	const der = Uint8Array.from([48, 3, 2, 1, 1]);
	const sent = { "client-cert": `:${Buffer.from(der).toString("base64")}:` };
	let seen: HttpRequest["source"]["clientCertificate"];
	const reading = handlers([
		{
			method: "GET",
			path: "/",
			handle: (request) => {
				seen = request.source.clientCertificate;
				return { status: 204 };
			},
		},
	]);
	const forwarding = (trusted: string[]) => ({
		"trusted-proxies": trusted,
		"client-certificate": { dialect: "rfc9440" },
	});

	it("is handed to a handler as a trusted proxy forwards it, with no warning", async () => {
		const { runtime, count } = warning();
		await fetch(await serveWith(reading, forwarding(["127.0.0.1"]), runtime), { headers: sent });
		expect(seen).toEqual({ kind: "certificate", leaf: der, chain: [] });
		expect(count("http.client_certificate_ignored")).toBe(0);
	});

	it("is ignored from a peer not trusted, with a warning once a minute", async () => {
		const { runtime, count } = warning();
		const base = await serveWith(reading, forwarding([]), runtime);
		await fetch(base, { headers: sent });
		expect(seen).toBeUndefined();
		await fetch(base, { headers: sent });
		expect(count("http.client_certificate_ignored")).toBe(1);
	});

	it("is read where the operator names it, in a form it names", async () => {
		const forwarded = (certificate: unknown) => boot({ "client-certificate": certificate });
		await expect(forwarded({ dialect: "rfc9440" })).resolves.toBeDefined();
		await expect(forwarded({ dialect: "pem", header: "x-client-cert" })).resolves.toBeDefined();
		const xfcc = await forwarded({ dialect: "xfcc" });
		expect(xfcc.get(certificateForwarding)).toEqual({ configured: true });
		expect((await boot()).get(certificateForwarding)).toEqual({ configured: false });
		for (const bad of [
			{ dialect: "pem" },
			{ dialect: "der" },
			{ dialect: "rfc9440", header: "Bad Name" },
			{ dialect: "xfcc", "chain-header": "x-chain" },
		]) {
			await expect(forwarded(bad), JSON.stringify(bad)).rejects.toBeInstanceOf(BootRefused);
		}
	});
});

describe("request bodies", () => {
	const gate = policy("test.json-gate");
	const object = JSON.stringify({ a: "1", nested: { b: [2] } });
	const large = JSON.stringify({ a: "x".repeat(70 * 1024) });
	/** What a handler read of the name `a`. */
	const read = (request: HttpRequest) => ({
		json: request.json,
		form: request.form.get("a"),
		fields: request.fields.get("a"),
	});

	/** Routes taking each set of bodies; the requests handled, what the gate saw, ways to post. */
	async function servedBodies() {
		const handled: HttpRequest[] = [];
		const gated: number[] = [];
		const route = (path: string, takes?: Route["takes"]): Route => ({
			method: "POST",
			path,
			...(takes ? { takes } : {}),
			...(path === "/form" || path === "/json" ? { uses: [use(gate)] } : {}),
			handle: (request) => {
				handled.push(request);
				return { status: 204 };
			},
		});
		const base = await serveWith(
			handlers(
				[
					route("/json", ["json"]),
					route("/form", ["form"]),
					route("/both", ["form", "json"]),
					route("/optional", ["form", "json", "none"]),
					route("/loose"),
				],
				[
					applying(gate, (request) => {
						gated.push(request.fields.size);
						return request.headers.get("x-shut") ? { status: 403 } : "pass";
					}),
				],
			),
		);
		const post = (path: string, type: string, body: string, headers = {}) =>
			fetch(`${base}${path}`, {
				method: "POST",
				headers: { "content-type": type, ...headers },
				body,
			}).then((res) => res.status);
		const untyped = (path: string, body?: Uint8Array) =>
			fetch(`${base}${path}`, { method: "POST", ...(body ? { body } : {}) }).then((r) => r.status);
		return { handled, gated, post, untyped };
	}

	it("reads a JSON object for a route that takes JSON: frozen, its string members as fields, others as mistyped", async () => {
		const { handled, post } = await servedBodies();
		expect(await post("/json", "application/json; charset=utf-8", object)).toBe(204);
		expect(await post("/json", "application/json", JSON.stringify({ n: null, a: "1" }))).toBe(204);
		expect(await post("/json", "application/json", JSON.stringify({ a: "1" }))).toBe(204);
		expect(
			handled.map((request) => ({
				json: request.json,
				nestedFrozen: Object.isFrozen(request.json?.nested),
				formSize: request.form.size,
				fields: [...request.fields],
				mistyped: request.mistyped && [...request.mistyped],
			})),
		).toEqual([
			{
				json: { a: "1", nested: { b: [2] } },
				nestedFrozen: true,
				formSize: 0,
				fields: [["a", ["1"]]],
				mistyped: ["nested"],
			},
			{
				json: { n: null, a: "1" },
				nestedFrozen: true,
				formSize: 0,
				fields: [["a", ["1"]]],
				mistyped: ["n"],
			},
			{
				json: { a: "1" },
				nestedFrozen: true,
				formSize: 0,
				fields: [["a", ["1"]]],
				mistyped: undefined,
			},
		]);
		const fields = handled[2]?.fields as unknown as Map<string, never>;
		expect(() => fields.delete("a")).toThrow(TypeError);
		expect(Object.isFrozen(fields.get("a"))).toBe(true);
	});

	it("answers 415, 400 and 413 for a body it cannot take, after the route's policies have seen it", async () => {
		const { handled, gated, post } = await servedBodies();
		expect(await post("/json", "application/x-www-form-urlencoded", "a=1")).toBe(415);
		for (const unread of ["[1]", "null", "{nope", '{"a":"1","a":"2"}']) {
			expect(await post("/json", "application/json", unread), unread).toBe(400);
		}
		expect(await post("/json", "application/json", large)).toBe(413);
		expect(await post("/form", "application/json", object)).toBe(415);
		expect(await post("/form", "application/x-www-form-urlencoded", "a=%C3%28")).toBe(400);
		expect(gated).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
		expect(await post("/json", "application/json", object, { "x-shut": "1" })).toBe(403);
		expect(await post("/json", "application/json", "{nope", { "x-shut": "1" })).toBe(403);
		expect(handled).toEqual([]);
	});

	it("reads each body by its type on a route that takes several; any other, or none, is 415", async () => {
		const { handled, post, untyped } = await servedBodies();
		expect(await post("/form", "application/x-www-form-urlencoded", "a=1&a=2")).toBe(204);
		expect(await post("/both", "application/x-www-form-urlencoded", "a=1")).toBe(204);
		expect(await post("/both", "application/json", object)).toBe(204);
		expect(await post("/both", "text/plain", "a=1")).toBe(415);
		expect(await untyped("/both")).toBe(415);
		expect(handled.map(read)).toEqual([
			{ json: undefined, form: ["1", "2"], fields: ["1", "2"] },
			{ json: undefined, form: ["1"], fields: ["1"] },
			{ json: { a: "1", nested: { b: [2] } }, form: undefined, fields: ["1"] },
		]);
	});

	it("answers a request without a body on a route that also takes none, but not an untyped body", async () => {
		const { handled, post, untyped } = await servedBodies();
		expect(await untyped("/optional")).toBe(204);
		expect(await untyped("/optional", new Uint8Array([97, 61, 49]))).toBe(415);
		expect(await post("/optional", "text/plain", "a=1")).toBe(415);
		expect(await post("/optional", "application/json", object)).toBe(204);
		expect(handled.map(read)).toEqual([
			{ json: undefined, form: undefined, fields: undefined },
			{ json: { a: "1", nested: { b: [2] } }, form: undefined, fields: ["1"] },
		]);
	});

	it("reads a form on a route that declares nothing, and ignores any other body", async () => {
		const { handled, post } = await servedBodies();
		expect(await post("/loose", "application/json", object)).toBe(204);
		expect(await post("/loose", "application/x-www-form-urlencoded", "a=1")).toBe(204);
		expect(handled.map(read)).toEqual([
			{ json: undefined, form: undefined, fields: undefined },
			{ json: undefined, form: ["1"], fields: ["1"] },
		]);
	});
});

describe("HEAD", () => {
	it("answers HEAD on a GET route with the same status and headers and no body", async () => {
		const methods: string[] = [];
		const base = await serveWith(
			handlers([
				{
					method: "GET",
					path: "/doc",
					handle: (request) => {
						methods.push(request.method);
						return { status: 200, headers: { etag: '"1"' }, body: { json: { a: "b" } } };
					},
				},
				{ method: "POST", path: "/post", handle: () => ({ status: 204 }) },
			]),
		);
		const got = await fetch(`${base}/doc`);
		const head = await fetch(`${base}/doc`, { method: "HEAD" });
		expect(head.status).toBe(200);
		expect(await head.text()).toBe("");
		// The client closes after a HEAD; the connection's own headers differ for that alone.
		const own = ["date", "connection", "keep-alive"];
		const without = (res: Response) => [...res.headers].filter(([name]) => !own.includes(name));
		expect(without(head)).toEqual(without(got));
		expect(head.headers.get("content-length")).toBe(String((await got.text()).length));
		expect(methods).toEqual(["GET", "HEAD"]);
		const post = await fetch(`${base}/post`, { method: "HEAD" });
		expect([post.status, post.headers.get("allow")]).toEqual([405, "POST"]);
	});
});

describe("cross-origin routes", () => {
	const app = "https://app.example";
	const failing = policy("test.cors-failing");
	const crossOrigin = handlers(
		[
			{
				method: "POST",
				path: "/token",
				cors: { headers: ["content-type", "dpop"], exposes: ["dpop-nonce"] },
				handle: () => ({ status: 200, headers: { vary: "Accept" }, body: { json: {} } }),
			},
			{ method: "GET", path: "/token", cors: {}, handle: () => ({ status: 200, body: "doc" }) },
			{
				method: "GET",
				path: "/down",
				cors: {},
				uses: [use(failing)],
				handle: () => ({ status: 204 }),
			},
			{ method: "GET", path: "/plain", handle: () => ({ status: 204 }) },
		],
		[
			applying(failing, async () => {
				throw new Unavailable("test");
			}),
		],
	);
	const from = (origin: string, init: RequestInit = {}) => ({
		...init,
		headers: { origin, ...(init.headers as Record<string, string>) },
	});
	const cors = (res: Response) =>
		[...res.headers].filter(([name]) => name.startsWith("access-control-") || name === "vary");

	it("lets an origin the operator lists read a declared route, naming that origin and never credentials", async () => {
		const base = await serveWith(crossOrigin, { "cors-origins": [app] });
		const posted = await fetch(`${base}/token`, from(app, { method: "POST" }));
		expect(posted.status).toBe(200);
		expect(cors(posted)).toEqual([
			["access-control-allow-origin", app],
			["access-control-expose-headers", "dpop-nonce"],
			["vary", "Accept, Origin"],
		]);
		const got = await fetch(`${base}/token`, from(app));
		expect(cors(got)).toEqual([
			["access-control-allow-origin", app],
			["vary", "Origin"],
		]);
		const head = await fetch(`${base}/token`, from(app, { method: "HEAD" }));
		expect(cors(head)).toEqual(cors(got));
		const down = await fetch(`${base}/down`, from(app));
		expect([down.status, down.headers.get("access-control-allow-origin")]).toEqual([503, app]);
	});

	it("gives an origin it does not list, and a route that does not declare it, nothing to read by", async () => {
		const base = await serveWith(crossOrigin, { "cors-origins": [app] });
		for (const origin of ["https://other.example", "https://app.example.evil", "null"]) {
			const res = await fetch(`${base}/token`, from(origin, { method: "POST" }));
			expect([res.status, cors(res)]).toEqual([200, [["vary", "Accept, Origin"]]]);
		}
		const plain = await fetch(`${base}/plain`, from(app));
		expect([plain.status, cors(plain)]).toEqual([204, []]);
		const none = await serveWith(crossOrigin);
		expect(cors(await fetch(`${none}/token`, from(app)))).toEqual([["vary", "Origin"]]);
	});

	it("answers a preflight for a declared route with what that route takes", async () => {
		const base = await serveWith(crossOrigin, { "cors-origins": [app] });
		const preflight = (origin: string, method: string, path = "/token") =>
			fetch(
				`${base}${path}`,
				from(origin, {
					method: "OPTIONS",
					headers: { "access-control-request-method": method },
				}),
			);
		const allowed = await preflight(app, "POST");
		expect(allowed.status).toBe(204);
		expect(cors(allowed)).toEqual([
			["access-control-allow-headers", "content-type, dpop"],
			["access-control-allow-methods", "POST, GET"],
			["access-control-allow-origin", app],
			["access-control-max-age", "600"],
			["vary", "Origin"],
		]);
		for (const refused of [
			await preflight("https://other.example", "POST"),
			await preflight(app, "DELETE"),
		]) {
			expect([refused.status, cors(refused)]).toEqual([204, [["vary", "Origin"]]]);
		}
		const plain = await preflight(app, "GET", "/plain");
		expect([plain.status, cors(plain)]).toEqual([405, []]);
		const head = await preflight(app, "HEAD");
		expect(head.headers.get("access-control-allow-origin")).toBe(app);
		const bare = await fetch(`${base}/token`, from(app, { method: "OPTIONS" }));
		expect(bare.status).toBe(405);
		const asking = { "access-control-request-method": "POST" };
		const posted = await fetch(`${base}/token`, from(app, { method: "POST", headers: asking }));
		expect([posted.status, await posted.text()]).toEqual([200, "{}"]);
	});

	it("refuses an origin that is not https, not an origin, or a pattern", async () => {
		for (const origin of [
			"http://app.example",
			"https://app.example/",
			"https://app.example/x",
			"https://*.example",
		]) {
			await expect(boot({ "cors-origins": [origin] })).rejects.toThrow(BootRefused);
		}
	});
});

describe("limits", () => {
	/** Opens a connection, sends `sent`, and resolves with all it reads once the server closes it. */
	function stalled(port: number, sent: string): Promise<string> {
		const socket = connect(port, "127.0.0.1", () => socket.write(sent));
		let text = "";
		socket.on("data", (chunk) => {
			text += chunk.toString();
		});
		socket.on("error", () => {});
		return new Promise((resolve) => socket.on("close", () => resolve(text)));
	}
	const routes = handlers([
		{ method: "POST", path: "/p", takes: ["form"], handle: () => ({ status: 204 }) },
	]);

	it("answers 408 and closes a connection whose headers are not all sent within headers-timeout", async () => {
		const base = await serveWith(routes, { "headers-timeout": "1s", "request-timeout": "5s" });
		const started = Date.now();
		const text = await stalled(Number(new URL(base).port), "GET /p HTTP/1.1\r\nHost: x\r\n");
		expect(text).toMatch(/^HTTP\/1\.1 408 /);
		expect(Date.now() - started).toBeLessThan(4000);
	});

	it("answers 408 and closes a connection whose body is not all sent within request-timeout", async () => {
		const base = await serveWith(routes, { "headers-timeout": "1s", "request-timeout": "2s" });
		const started = Date.now();
		const head =
			"POST /p HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 10\r\n\r\na=";
		const text = await stalled(Number(new URL(base).port), head);
		expect(text).toMatch(/^HTTP\/1\.1 408 /);
		expect(Date.now() - started).toBeGreaterThanOrEqual(1500);
	});

	it("closes a connection past max-connections as it arrives, and serves the one it holds", async () => {
		const base = await serveWith(routes, { "max-connections": 1 });
		const port = Number(new URL(base).port);
		const held = connect(port, "127.0.0.1");
		held.on("error", () => {});
		await new Promise((resolve) => held.once("connect", resolve));
		await new Promise((resolve) => setTimeout(resolve, 50));
		expect(await stalled(port, "GET /p HTTP/1.1\r\nHost: x\r\n\r\n")).toBe("");
		held.destroy();
	});
});

describe("test requests", () => {
	it("give fields from their JSON or form, as the server does", () => {
		const form = new Map([["a", ["1", "2"]]]);
		expect([...testRequest({ form }).fields]).toEqual([...form]);
		expect(testRequest({ form }).fields.repeated()).toEqual(["a"]);
		expect(testRequest({ query: new Map([["q", ["1"]]]) }).query.single("q")).toBe("1");
		expect([...testRequest({ json: { a: "1", n: 2 } }).fields]).toEqual([["a", ["1"]]]);
		expect([...(testRequest({ json: { a: "1", n: 2 } }).mistyped ?? [])]).toEqual(["n"]);
		expect(testRequest({ form }).mistyped).toBeUndefined();
		const mistyped = testRequest({ json: { n: 2 } }).mistyped as Set<string>;
		expect(() => mistyped.add("x")).toThrow(TypeError);
		expect(() => mistyped.delete("n")).toThrow(TypeError);
		expect(() => mistyped.clear()).toThrow(TypeError);
		expect(testRequest().fields.size).toBe(0);
	});

	it("are read-only as the server's are", () => {
		const json = { a: "1", nested: { b: [2] } };
		const sent = new Map([["x", "1"]]);
		const request = testRequest({ json, headers: sent });
		expect(() => (request.headers as Map<string, string>).set("y", "2")).toThrow(TypeError);
		expect(sent.set("y", "2").get("y")).toBe("2");
		expect(Object.isFrozen(request.json?.nested)).toBe(true);
		expect(Object.isFrozen(json)).toBe(false);
		expect(Object.isFrozen(request.source)).toBe(true);
		expect(Object.isFrozen(request)).toBe(true);
	});
});
