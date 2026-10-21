import { defineModule } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import { type FactorStore, factorStore, type StoredFactors } from "../src/store.ts";

/** mfa's factor store on the records stand-in, its lists kept without end on the given clock; `down` makes calls unavailable, and `hooks.beforeSave` runs before each save, as a request racing it would. */
export function memoryFactors(now: () => number = () => 0) {
	const stand = memoryRecords<StoredFactors>(now, { shards: 1, perShard: 1 });
	const down = unavailableSwitch<FactorStore>("factor-store");
	const hooks: { beforeSave?: (key: string) => Promise<void> } = {};
	const factors: FactorStore = down.wrap({
		save: async (key, record) => {
			await hooks.beforeSave?.(key);
			return stand.records.create(key, record, "endless");
		},
		read: stand.records.read,
		update: stand.records.change,
		scan: stand.records.scan,
	});
	const module = defineModule({ name: "factor-store" }, (m) => [
		m.provide(factorStore).by(() => factors),
	]);
	return { module, factors, down, hooks, ...stand };
}
