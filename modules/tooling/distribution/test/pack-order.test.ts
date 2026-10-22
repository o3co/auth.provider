import { expect, it } from "vitest";
import { packOrder } from "../src/pack-order.ts";

const declared = [
	{ dir: "foundation", entrances: [] },
	{ dir: "oauth", entrances: [] },
	{ dir: "scaffold", index: "index.json", entrances: ["@o3co/create-auth-provider"] },
];

it("packs every bundle but the index's first, then the index's bundle and the entrances", () => {
	expect(packOrder(["oauth", "scaffold", "create-auth-provider", "foundation"], declared)).toEqual({
		first: ["foundation", "oauth"],
		index: { dir: "scaffold", file: "index.json" },
		last: ["scaffold", "create-auth-provider"],
	});
});

it("refuses no bundle or two declaring the index, and a declared one not built", () => {
	expect(packOrder(["oauth"], [{ dir: "oauth", entrances: [] }])).toEqual({
		problem: "0 bundles declare the index, where one does",
	});
	expect(
		packOrder(
			["a", "b"],
			[
				{ dir: "a", index: "i.json", entrances: [] },
				{ dir: "b", index: "i.json", entrances: [] },
			],
		),
	).toEqual({
		problem: "2 bundles declare the index, where one does",
	});
	expect(packOrder(["foundation", "oauth", "scaffold"], declared)).toEqual({
		problem: "create-auth-provider: declared, but not built",
	});
});
