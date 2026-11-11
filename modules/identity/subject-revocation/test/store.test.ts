import { expect, it } from "vitest";
import { fenceWhere } from "../src/store.ts";
import { boundaryStoreContract } from "../src/testing.ts";
import { memoryBoundaries } from "./stores.ts";

boundaryStoreContract("records stand-in", async () => {
	const { boundaries, kept, advanceStore, raceFence, erasure } = memoryBoundaries();
	return {
		boundaries,
		advance: advanceStore,
		raceNextUpdate: (_subject, change) => kept.raceNextChange(change),
		raceNextFence: (_subject, change) => raceFence(change),
		enableErasure: async () => {
			erasure.on = true;
		},
	};
});

it("offers a fence only where the store can fence, never making one where it cannot", () => {
	const made = async () => ({ before: undefined, after: undefined });
	let asked = 0;
	const fence = () => {
		asked += 1;
		return made;
	};
	expect(fenceWhere(false, fence)).toEqual({});
	expect(asked).toBe(0);
	expect(fenceWhere(true, fence)).toEqual({ fence: made });
	expect(asked).toBe(1);
});
