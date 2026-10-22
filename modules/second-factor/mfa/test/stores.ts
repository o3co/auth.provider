import { defineModule } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import { type FactorStore, factorStore, type StoredFactors } from "../src/store.ts";
import { updatingTogether } from "../src/testing.ts";

/**
 * mfa's factor store on the records stand-in, its lists kept without end on the given clock; `down`
 * makes calls unavailable, and `hooks.beforeSave` runs before each save, `hooks.afterRead` after each
 * read has taken its answer, as a request racing it would, and `hooks.afterTogether` after a write
 * of a list and a claim together has taken effect, as an answer lost would.
 */
export function memoryFactors(now: () => number = () => 0) {
	const stand = memoryRecords<StoredFactors>(now, { shards: 1, perShard: 1 });
	const down = unavailableSwitch<FactorStore>("factor-store");
	const hooks: {
		beforeSave?: (key: string) => Promise<void>;
		afterRead?: (key: string) => Promise<void>;
		afterTogether?: (() => Promise<void>) | undefined;
	} = {};
	const joint = updatingTogether(stand.records);
	const factors: FactorStore = down.wrap({
		save: async (key, record) => {
			await hooks.beforeSave?.(key);
			return stand.records.create(key, record, "endless");
		},
		read: async (key) => {
			const found = await stand.records.read(key);
			await hooks.afterRead?.(key);
			return found;
		},
		update: stand.records.change,
		scan: stand.records.scan,
		updateTogether: async (...args: Parameters<typeof joint>) => {
			const changed = await joint(...args);
			await hooks.afterTogether?.();
			return changed;
		},
	});
	const module = defineModule({ name: "factor-store" }, (m) => [
		m.provide(factorStore).by(() => factors),
	]);
	return { module, factors, down, hooks, ...stand };
}
