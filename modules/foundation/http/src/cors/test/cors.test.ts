import { BootRefused, Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { applying, policy, use } from "../../contract.ts";
import { boot, handlers, serveWith } from "../../serving/test/serve.ts";

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
