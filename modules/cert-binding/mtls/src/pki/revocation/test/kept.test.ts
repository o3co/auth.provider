import { expect, it } from "vitest";
import { expiring } from "../kept.ts";

it("holds what it keeps to a budget of weight beside its number of entries, the oldest going first, and keeps none weighing more alone", () => {
	const kept = expiring<number>(10, () => 0, { most: 10, weigh: (weight) => weight });
	kept.set("a", 4, 1);
	kept.set("b", 4, 1);
	// 4 + 4 + 4 is past 10: the oldest goes.
	kept.set("c", 4, 1);
	expect(["a", "b", "c"].map((key) => kept.get(key)?.value)).toEqual([undefined, 4, 4]);
	// Set again, a key's own weight is not counted twice.
	kept.set("c", 6, 1);
	expect(["b", "c"].map((key) => kept.get(key)?.value)).toEqual([4, 6]);
	// Past the budget alone: not kept, and nothing else goes for it.
	kept.set("d", 11, 1);
	expect(["b", "c", "d"].map((key) => kept.get(key)?.value)).toEqual([4, 6, undefined]);
});
