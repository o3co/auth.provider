import { selectionRecords } from "@mod/claims-selection";
import { selectionRecordsContract } from "@mod/claims-selection/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

for (const phase of ["reader", "indexed"] as const) {
	selectionRecordsContract(
		`claims-selection-store on subject-records, on a simulated replicated store (${phase})`,
		async () => {
			const simulated = simulatedStore();
			if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
			const app = await assemble({
				modules: [simulated.module, wiring],
				config: kernelConfig(),
				runtime,
			});
			return {
				records: app.get(selectionRecords),
				advance: (ms: number) => simulated.shiftClock(ms),
				loseNextAnswer: () => simulated.loseNextReply(),
				failover: () => simulated.failover(),
				restart: () => simulated.restart(),
				pressMemory: () => simulated.pressMemory(),
			};
		},
	);
}
