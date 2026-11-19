import { type ErasureMaintenance, erasureMaintenance } from "@mod/account-erasure";
import { defineModule } from "@mod/kernel";
import { store, storeControl, storeUpkeep } from "@mod/store";
import { subjectRecordsPhase } from "@mod/subject-records";

// Holds nothing of its own, so it is safe on many instances.
export default defineModule(
	{
		name: "account-erasure-store",
		replicaSafe: true,
		takes: [storeUpkeep, storeControl, store],
	},
	(m) => [
		m.provide(erasureMaintenance).by(async (c): Promise<ErasureMaintenance> => {
			const upkeep = await c.get(storeUpkeep);
			const control = await c.get(storeControl);
			// Taken only to hand to subject-records' phase write, which asks whether it pairs.
			const pairing = await c.get(store);
			const declared = Object.freeze(structuredClone(upkeep.declared()));
			// Each answer copied plainly: none of store's objects reaches erasure.
			return {
				record: async () => structuredClone(await control.control()),
				enter: async () => structuredClone(await upkeep.enterMaintenance()),
				leave: async () => structuredClone(await upkeep.leaveMaintenance()),
				mark: async (name, value) => structuredClone(await upkeep.mark(name, value)),
				require: async (names) => structuredClone(await upkeep.require(names)),
				kept: async () => structuredClone(await upkeep.kept()),
				retire: async (name) => structuredClone(await upkeep.retire(name)),
				honours: async (guarantees) => structuredClone(await upkeep.honours(guarantees)),
				sweep: async (name, cursor) => structuredClone(await upkeep.sweep(name, cursor)),
				phase: () => subjectRecordsPhase.read(control),
				writePhase: async () =>
					subjectRecordsPhase.writeWith(await control.control(), pairing, upkeep.mark),
				alone: async () => structuredClone(await upkeep.alone()),
				declared: () => declared,
			};
		}),
	],
);
