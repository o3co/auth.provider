import { createHash } from "node:crypto";
import { connect } from "node:net";
import { assemble, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { afterEach, describe, expect, it } from "vitest";
import { type Loads, listening, type Route, routes } from "../../contract.ts";
import http from "../../module.ts";
import { declared } from "../../serving/test/declared.ts";

const quiet = quietRuntime({
	clock: { now: () => 0 },
	random: { bytes: (n) => new Uint8Array(n) },
});

/** Every answer's headers, as the standalone build sent them. */
const expected = {
	"content-security-policy":
		"default-src 'none';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'none';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests",
	"cross-origin-opener-policy": "same-origin",
	"cross-origin-resource-policy": "same-origin",
	"origin-agent-cluster": "?1",
	"referrer-policy": "no-referrer",
	"strict-transport-security": "max-age=31536000; includeSubDomains",
	"x-content-type-options": "nosniff",
	"x-dns-prefetch-control": "off",
	"x-download-options": "noopen",
	"x-frame-options": "SAMEORIGIN",
	"x-permitted-cross-domain-policies": "none",
	"x-xss-protection": "0",
};

const carried = (res: Response) =>
	Object.fromEntries(Object.keys(expected).map((name) => [name, res.headers.get(name)]));

let stop: () => Promise<void> = async () => {};
afterEach(async () => {
	await stop();
	stop = async () => {};
});

async function serveWith(list: readonly Route[]) {
	const handlers = defineModule({ name: "handlers", takes: [] }, (m) =>
		list.map((route) => m.contribute(routes).by(() => declared(route))),
	);
	const app = await assemble({
		modules: [http, handlers],
		config: { ...kernelConfig(), http: { port: 0, "cors-origins": ["https://app.example"] } },
		runtime: quiet,
	});
	await app.start();
	stop = () => app.stop(1000);
	return `http://127.0.0.1:${app.get(listening).port()}`;
}

/** Sends raw bytes and gives the answer's text. */
function raw(port: number, request: string): Promise<string> {
	return new Promise((resolve, reject) => {
		const socket = connect(port, "127.0.0.1", () => socket.end(request));
		let text = "";
		socket.on("data", (chunk) => {
			text += chunk.toString();
		});
		socket.on("end", () => resolve(text));
		socket.on("error", reject);
	});
}

describe("security headers", () => {
	const answering: Route[] = [
		{
			method: "GET",
			path: "/page",
			handle: () => ({ status: 200, headers: { vary: "Accept" }, body: "<p>hi</p>" }),
		},
		{ method: "POST", path: "/json", takes: ["json"], handle: () => ({ status: 204 }) },
		{ method: "POST", path: "/cors", cors: {}, handle: () => ({ status: 204 }) },
		{
			method: "GET",
			path: "/down",
			handle: () => {
				throw new Unavailable("store");
			},
		},
		{
			method: "GET",
			path: "/boom",
			handle: () => {
				throw new Error("boom");
			},
		},
		{ method: "GET", path: "/void", handle: () => undefined as never },
	];

	it("go on every answer, whatever answers it, with the route's own headers kept [rfc9700-4.16-a] [rfc9700-4.16-b] [rfc9700-4.16-d]", async () => {
		const base = await serveWith(answering);
		const asked: [string, RequestInit, number][] = [
			["/page", {}, 200],
			["/page", { method: "HEAD" }, 200],
			["/nope", {}, 404],
			["/page", { method: "DELETE" }, 405],
			["/json", { method: "POST", body: "a=1" }, 415],
			["/down", {}, 503],
			["/boom", {}, 500],
			["/void", {}, 500],
			[
				"/cors",
				{
					method: "OPTIONS",
					headers: { origin: "https://app.example", "access-control-request-method": "POST" },
				},
				204,
			],
		];
		for (const [path, init, status] of asked) {
			const res = await fetch(`${base}${path}`, init);
			expect([path, res.status, carried(res)]).toEqual([path, status, expected]);
		}
		expect((await fetch(`${base}/page`)).headers.get("vary")).toBe("Accept");
	});

	it("replace a route's own, its policy included [rfc9700-4.16-a]", async () => {
		const base = await serveWith([
			{
				method: "GET",
				path: "/own",
				handle: () => ({
					status: 200,
					headers: {
						"X-Frame-Options": "ALLOWALL",
						"referrer-policy": "unsafe-url",
						"content-security-policy": "default-src 'none'",
					},
				}),
			},
		]);
		const res = await fetch(`${base}/own`);
		expect(carried(res)).toEqual(expected);
	});

	it("go on the 400 to a request target that is not a URL", async () => {
		const base = await serveWith([]);
		const text = await raw(
			Number(new URL(base).port),
			"GET http://[ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
		);
		expect(text).toMatch(/^HTTP\/1\.1 400/);
		for (const [name, value] of Object.entries(expected)) {
			expect(text.toLowerCase()).toContain(`\r\n${name}: ${value.toLowerCase()}\r\n`);
		}
	});
});

describe("an answer that declares what it loads", () => {
	const script = "location.href='/next'";
	const hash = `'sha256-${createHash("sha256").update(script).digest("base64")}'`;
	const page = (loads: Loads): Route => ({
		method: "GET",
		path: "/page",
		handle: () => ({ status: 200, headers: { "content-type": "text/html" }, body: "<p>", loads }),
	});

	it("gets a policy allowing those frames and scripts and nothing else; other answers keep theirs", async () => {
		const base = await serveWith([
			page({
				frames: ["https://a.example", "http://b.example:8443", "https://a.example"],
				scripts: [script],
			}),
			{ method: "GET", path: "/other", handle: () => ({ status: 200 }) },
		]);
		const res = await fetch(`${base}/page`);
		expect(carried(res)).toEqual({
			...expected,
			"content-security-policy": `default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; frame-src https://a.example http://b.example:8443; script-src ${hash}`,
		});
		const head = await fetch(`${base}/page`, { method: "HEAD" });
		expect(head.headers.get("content-security-policy")).toBe(
			res.headers.get("content-security-policy"),
		);
		expect(carried(await fetch(`${base}/other`))).toEqual(expected);
	});

	it("names only what it declares", async () => {
		const base = await serveWith([
			page({ frames: ["https://a.example"] }),
			{ ...page({ scripts: [script] }), path: "/script" },
			{ ...page({}), path: "/none" },
		]);
		const policyOf = async (path: string) =>
			(await fetch(`${base}${path}`)).headers.get("content-security-policy");
		const strict =
			"default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
		expect(await policyOf("/page")).toBe(`${strict}; frame-src https://a.example`);
		expect(await policyOf("/script")).toBe(`${strict}; script-src ${hash}`);
		expect(await policyOf("/none")).toBe(strict);
	});

	it("lets a page post its forms to this origin alone where it says so, nothing else widened", async () => {
		const base = await serveWith([
			page({ forms: "self" }),
			{ ...page({ forms: "self", scripts: [script] }), path: "/moving" },
		]);
		const policyOf = async (path: string) =>
			(await fetch(`${base}${path}`)).headers.get("content-security-policy");
		const formOnly =
			"default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
		expect(await policyOf("/page")).toBe(formOnly);
		expect(await policyOf("/moving")).toBe(`${formOnly}; script-src ${hash}`);
	});

	it("takes its declaration over a policy of its own", async () => {
		const base = await serveWith([
			{
				method: "GET",
				path: "/page",
				handle: () => ({
					status: 200,
					headers: { "Content-Security-Policy": "default-src *" },
					loads: { frames: ["https://a.example"] },
				}),
			},
		]);
		const res = await fetch(`${base}/page`);
		expect(res.headers.get("content-security-policy")).toBe(
			"default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; frame-src https://a.example",
		);
	});

	it("is answered 500, its policy unsent, when a frame is not an origin a policy can name", async () => {
		const base = await serveWith(
			[
				"https://[::1]",
				"https://a_b.example",
				"https://a.example/path",
				"https://a.example; script-src *",
				"https://a.example *",
				"javascript://a.example",
				"*",
			].map((frame, i) => ({ ...page({ frames: [frame] }), path: `/p${i}` })),
		);
		for (let i = 0; i < 7; i++) {
			const res = await fetch(`${base}/p${i}`);
			expect([i, res.status, carried(res)]).toEqual([i, 500, expected]);
		}
	});
});
