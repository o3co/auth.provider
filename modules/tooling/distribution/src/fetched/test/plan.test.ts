import { describe, expect, it } from "vitest";
import type { Lookup } from "../../release/published.ts";
import { fetchPlan } from "../plan.ts";

const unit = (dir: string) => ({ dir, name: `@o3co/auth-provider-${dir}` });
const order = {
	first: [unit("foundation"), unit("oauth")],
	index: unit("scaffold"),
	last: [unit("scaffold"), { dir: "create-auth-provider", name: "@o3co/create-auth-provider" }],
};
const there = (integrity = "sha512-R"): Lookup => ({ kind: "present", integrity });
const looked = (present: Record<string, Lookup>) =>
	new Map(
		[...order.first, ...order.last].map((u) => [
			u.name,
			present[u.name] ?? ({ kind: "absent" } as Lookup),
		]),
	);

describe("what a pack takes from the registry", () => {
	it("packs everything where npm holds nothing of this version", () => {
		expect(fetchPlan(order, looked({}))).toEqual({ fetch: [] });
	});

	it("takes from the registry each package npm holds, with the integrity npm gave it", () => {
		const plan = fetchPlan(order, looked({ "@o3co/auth-provider-foundation": there("sha512-F") }));
		expect(plan).toEqual({ fetch: [{ ...unit("foundation"), integrity: "sha512-F" }] });
		const all = fetchPlan(
			order,
			looked({
				"@o3co/auth-provider-foundation": there(),
				"@o3co/auth-provider-oauth": there(),
				"@o3co/auth-provider-scaffold": there(),
			}),
		);
		expect("fetch" in all && all.fetch.map((u) => u.dir)).toEqual([
			"foundation",
			"oauth",
			"scaffold",
		]);
	});

	it("stops, for a person, where the index's bundle is on npm and a bundle it seals over is not", () => {
		expect(fetchPlan(order, looked({ "@o3co/auth-provider-scaffold": there() }))).toEqual({
			problems: [
				"@o3co/auth-provider-scaffold is on npm, but @o3co/auth-provider-foundation, @o3co/auth-provider-oauth, which its index seals over, are not: published out of order, it cannot be sealed again",
			],
		});
	});

	it("stops where npm's answer for a package cannot be read, as nothing then tells packing from fetching", () => {
		const failed: Lookup = { kind: "failed", why: "E500" };
		expect(fetchPlan(order, looked({ "@o3co/auth-provider-oauth": failed }))).toEqual({
			problems: ["@o3co/auth-provider-oauth: the registry's answer is unread (E500)"],
		});
	});
});
