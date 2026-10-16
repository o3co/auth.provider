import { defineModule } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import { type FactorStore, factorStore, type StoredFactors } from "../src/store.ts";

/** mfa's factor store on the records stand-in, its lists kept without end on the given clock; `down` makes calls unavailable. */
export function memoryFactors(now: () => number = () => 0) {
	const stand = memoryRecords<StoredFactors>(now, { shards: 1, perShard: 1 });
	const down = unavailableSwitch<FactorStore>("factor-store");
	const factors: FactorStore = down.wrap({
		save: (key, record) => stand.records.create(key, record, "endless"),
		read: stand.records.read,
		update: stand.records.change,
	});
	const module = defineModule({ name: "factor-store" }, (m) => [
		m.provide(factorStore).by(() => factors),
	]);
	return { module, factors, down, ...stand };
}
