import { connect } from "node:net";
import { contract, defineModule, type Module, Unavailable } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { describe, expect, it } from "vitest";
import {
	applying,
	type HttpRequest,
	type HttpResponse,
	jsonAnswer,
	listening,
	policy,
	type Route,
	use,
} from "../../contract.ts";

import {
	boot,
	handlers,
	quiet,
	rawStatus,
	refusalsOf,
	served,
	serveWith,
	warning,
} from "./serve.ts";

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
		await served.stop();
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

	it("serves a path from a route with a middle * for exactly one segment, the declaration literal earliest first", async () => {
		const base = await serveWith(
			handlers(
				(
					[
						["GET", "/fed/*", 201],
						["GET", "/fed/*/callback", 202],
						["POST", "/fed/*/callback", 203],
						["GET", "/m/*/c", 205],
						["GET", "/m/b/*", 206],
					] as const
				).map(([method, path, status]) => ({ method, path, handle: () => ({ status }) })),
			),
		);
		const port = Number(new URL(base).port);
		const status = (target: string, method = "GET") =>
			rawStatus(
				port,
				`${method} ${target} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`,
			);
		expect(await status("/fed/google")).toBe(201);
		expect(await status("/fed/google/callback")).toBe(202);
		expect(await status("/fed/google/callback", "POST")).toBe(203);
		expect(await status("/fed/google/callback/more")).toBe(201);
		// An empty segment, an escaped slash and dot segments reach no declaration they do not match.
		expect(await status("/fed//callback")).toBe(201);
		expect(await status("/fed/google%2Fcallback")).toBe(201);
		expect(await status("/fed/google/callback/..")).toBe(201);
		expect(await status("/fed/%2e%2e/callback")).toBe(404);
		expect(await status("/fed/x/../google/callback")).toBe(202);
		expect(await status("/fed/google", "POST")).toBe(405);
		expect(await status("/m/b/c")).toBe(206);
		expect(await status("/m/x/c")).toBe(205);
		expect(await status("/m/x/d")).toBe(404);
	});

	it("reaches the same declaration whatever order the routes are declared in, a trailing slash and case read as written, and HEAD only from the declaration reached", async () => {
		const declaredRoutes: Route[] = (
			[
				["GET", "/fed/*", 201],
				["POST", "/fed/*/callback", 203],
				["GET", "/h/*/x", 207],
				["GET", "/h/*", 208],
			] as const
		).map(([method, path, status]) => ({ method, path, handle: () => ({ status }) }));
		// A GET that changes state, which HEAD never reaches.
		const changing: Route = {
			method: "GET",
			path: "/fed/*/callback",
			changesState: true,
			crossSite: "a test route",
			unlimited: "a test route",
			handle: () => ({ status: 202 }),
		};
		for (const order of [[...declaredRoutes, changing], [...declaredRoutes, changing].reverse()]) {
			await served.stop();
			const port = Number(new URL(await serveWith(handlers(order))).port);
			const status = (target: string, method = "GET") =>
				rawStatus(
					port,
					`${method} ${target} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`,
				);
			expect(await status("/fed/google/callback")).toBe(202);
			expect(await status("/fed/google/callback", "POST")).toBe(203);
			expect(await status("/fed/google/callback/")).toBe(201);
			expect(await status("/fed/google/")).toBe(201);
			expect(await status("/fed/google/Callback")).toBe(201);
			expect(await status("/FED/google")).toBe(404);
			// HEAD is answered by the declaration a path reaches, never one broader than it.
			expect(await status("/fed/google/callback", "HEAD")).toBe(405);
			expect(await status("/fed/google", "HEAD")).toBe(201);
			expect(await status("/h/a/x", "HEAD")).toBe(207);
			expect(await status("/h/a/y", "HEAD")).toBe(208);
		}
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

	it("still answers what the route declares when noting throws, logging the failure by kind only [guarantee-8-b]", async () => {
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
		served.stop = () => app.stop(1000);
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
		const hanging = defineModule({ name: "hanging", takes: [] }, (m) => [
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

it("answers 500 for a JSON answer holding a member whose value is null, at any depth, logging the members' paths and never their values [oidc-core-13.3-a]", async () => {
	const recorded = recordingLog();
	const runtime = quietRuntime({ ...quiet, log: recorded.log });
	const base = await serveWith(
		handlers([
			{
				method: "GET",
				path: "/nulls",
				handle: () =>
					jsonAnswer(200, {
						kept: "secret-value",
						top: null,
						address: { locality: "x", region: null },
						list: [{ item: null }, null],
					}),
			},
			{ method: "GET", path: "/none", handle: () => jsonAnswer(200, { kept: "v", list: [1] }) },
		]),
		{},
		runtime,
	);
	const refused = await fetch(`${base}/nulls`);
	expect([refused.status, await refused.text()]).toEqual([500, ""]);
	expect(recorded.lines().filter((line) => line.level === "error")).toEqual([
		{
			level: "error",
			event: "http.failed",
			fields: { kind: "null_member", members: "top address.region list[0].item" },
		},
	]);
	expect(JSON.stringify(recorded.lines())).not.toContain("secret-value");
	expect((await fetch(`${base}/none`)).status).toBe(200);
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

it("logs a failure by its kind only, never its message [guarantee-8-b]", async () => {
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

it("refuses at boot two routes taking one method and path, naming the route", async () => {
	const route: Route = { method: "GET", path: "/x", handle: () => ({ status: 204 }) };
	const twice = handlers([route, { ...route, method: "POST" }, route]);
	expect(await refusalsOf(serveWith(twice))).toEqual([
		["http.routes:GET /x", "more than one contribution for the same key"],
	]);
});

it("refuses at boot two routes of one method and the same shape with a middle *, naming the route", async () => {
	const route: Route = { method: "GET", path: "/x/*/y", handle: () => ({ status: 204 }) };
	expect(await refusalsOf(serveWith(handlers([route, route])))).toEqual([
		["http.routes:GET /x/*/y", "more than one contribution for the same key"],
	]);
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
