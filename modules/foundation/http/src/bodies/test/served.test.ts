import { describe, expect, it } from "vitest";
import { applying, type HttpRequest, policy, type Route, use } from "../../contract.ts";
import { handlers, serveWith } from "../../serving/test/serve.ts";

it("reads form bodies with repeated names and ignores other bodies [rfc6749-10.14-b]", async () => {
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

it("answers 400 to a query whose percent-escapes are not UTF-8, and reads one that is [rfc6749-10.14-b]", async () => {
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

	it("reads a JSON object for a route that takes JSON: frozen, its string members as fields, others as mistyped [rfc6749-10.14-b]", async () => {
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

	it("answers 415, 400 and 413 for a body it cannot take, after the route's policies have seen it, a value's meaning left to its route [rfc6749-10.14-b]", async () => {
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
