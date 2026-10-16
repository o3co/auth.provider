import { boundaryStoreContract } from "../src/testing.ts";
import { memoryBoundaries } from "./stores.ts";

boundaryStoreContract("records stand-in", async () => {
	const { boundaries, kept, advanceStore } = memoryBoundaries();
	return {
		boundaries,
		advance: advanceStore,
		raceNextUpdate: (_subject, change) => kept.raceNextChange(change),
	};
});
