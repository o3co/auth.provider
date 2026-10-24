import { Unavailable } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { applying, policy, use } from "../../contract.ts";
import { handlers, refusalsOf, serveWith } from "../../serving/test/serve.ts";

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

	it("refuses at boot two rules for one policy", async () => {
		const ours = policy("shared.name");
		const twice = handlers([], [applying(ours, () => "pass"), applying(ours, () => "pass")]);
		expect(await refusalsOf(serveWith(twice))).toEqual([
			["http.policies", "more than one rule for a policy: shared.name"],
		]);
	});
});
