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
