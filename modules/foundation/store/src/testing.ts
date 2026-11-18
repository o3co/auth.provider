import { describe } from "vitest";
import type { z } from "zod";
import { batchesContract } from "./contract-batches/batches.ts";
import { faultsContract } from "./contract-faults/faults.ts";
import { contractKit, type StoreHarness } from "./contract-harness/harness.ts";
import { keysContract } from "./contract-keys/keys.ts";
import { marksContract } from "./contract-marks/marks.ts";
import { walkingContract } from "./contract-walking/walking.ts";
import { writerContract } from "./contract-writer/writer.ts";
import type { section } from "./section.ts";

export {
	contractSpaces,
	overwrite,
	type StoreHarness,
} from "./contract-harness/harness.ts";
export { plantValue } from "./planting/planting.ts";
export { type SimulatedStore, simulatedStore } from "./simulated/simulated.ts";
export {
	type UpkeepHarness,
	type UpkeepProcess,
	upkeepContract,
	upkeepSpaces,
} from "./upkeep/suite.ts";

/** The store contract, run against any implementation: each part in the order a reader meets it. */
export function storeContract(name: string, harness: StoreHarness): void {
	const kit = contractKit(harness);
	describe(`store contract: ${name}`, () => {
		keysContract(harness, kit);
		marksContract(harness, kit);
		batchesContract(harness, kit);
		walkingContract(harness, kit);
		writerContract(harness, kit);
		faultsContract(harness, kit);
	});
}

export type StoreSettings = z.input<typeof section>;

/** The store part of a test's configuration: the memory store, accepted though it forgets on restart. */
export function storeConfig(settings: Partial<StoreSettings> = {}) {
	return { store: { "accept-volatile": true, ...settings } };
}
