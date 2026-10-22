import { expect, it } from "vitest";
import { packOrder } from "../pack-order.ts";

const declared = [
	{ dir: "foundation", shipped: true, entrances: [] },
	{ dir: "oauth", shipped: true, entrances: [] },
	{ dir: "testing-kit", shipped: false, entrances: [] },
	{
		dir: "scaffold",
		shipped: true,
		index: "index.json",
		entrances: ["@o3co/create-auth-provider"],
	},
];

it("packs every bundle but the index's first, then the index's bundle and the entrances", () => {
	expect(packOrder(["oauth", "scaffold", "create-auth-provider", "foundation"], declared)).toEqual({
		first: ["foundation", "oauth"],
		index: { dir: "scaffold", file: "index.json" },
		last: ["scaffold", "create-auth-provider"],
	});
});

it("refuses no bundle or two declaring the index, and a declared one not built", () => {
	expect(packOrder(["oauth"], [{ dir: "oauth", shipped: true, entrances: [] }])).toEqual({
		problem: "0 bundles declare the index, where one does",
	});
	expect(
		packOrder(
			["a", "b"],
			[
				{ dir: "a", shipped: true, index: "i.json", entrances: [] },
				{ dir: "b", shipped: true, index: "i.json", entrances: [] },
			],
		),
	).toEqual({
		problem: "2 bundles declare the index, where one does",
	});
	expect(packOrder(["foundation", "oauth", "scaffold"], declared)).toEqual({
		problem: "create-auth-provider: declared, but not built",
	});
});

it("packs what the shipped bundles declare, refusing one not built and one built that none declares", () => {
	// A shipped bundle missing from the build is refused, so the index is never sealed without it.
	expect(packOrder(["oauth", "scaffold", "create-auth-provider"], declared)).toEqual({
		problem: "foundation: declared, but not built",
	});
	expect(
		packOrder(["foundation", "oauth", "stray", "scaffold", "create-auth-provider"], declared),
	).toEqual({ problem: "stray: built, but not declared to ship" });
	// An unshipped bundle is neither expected nor packed.
	expect(
		packOrder(["foundation", "oauth", "testing-kit", "scaffold", "create-auth-provider"], declared),
	).toEqual({ problem: "testing-kit: built, but not declared to ship" });
});
