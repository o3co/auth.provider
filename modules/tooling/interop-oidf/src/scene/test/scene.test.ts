import { describe, expect, it } from "vitest";
import { harnessConfig } from "../scene.ts";

const user = {
	identifier: "alice@example.test",
	password: "a password",
	name: "Alice Example",
	email: "alice@example.test",
	picture: "https://example.test/alice.png",
};

describe("what the harness asks of the app beyond the areas' scenes", () => {
	it("declares one acr, named by a URI, that a password login meets, for discovery to offer the suite", () => {
		const acr = harnessConfig({ user }).acr as { values: Record<string, string[][]> };
		const names = Object.keys(acr.values);
		expect(names).toHaveLength(1);
		for (const name of names) {
			expect(() => new URL(name)).not.toThrow();
			expect(acr.values[name]).toEqual([["pwd"]]);
		}
	});
});
