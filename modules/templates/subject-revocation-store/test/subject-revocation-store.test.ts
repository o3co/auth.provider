import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { boundaryStore } from "@mod/subject-revocation";
import { boundaryStoreContract } from "@mod/subject-revocation/testing";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

boundaryStoreContract(
	"subject-revocation-store on records, on a simulated replicated store",
	async () => {
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime,
		});
		const boundaries = app.get(boundaryStore);
		return {
			boundaries,
			advance: (ms) => simulated.shiftClock(ms),
			raceNextUpdate: (subject, change) =>
				simulated.beforeNext("replaceIf", "subject-revocation-store.boundaries", async () => {
					await boundaries.update(subject, change);
				}),
			loseNextAnswer: () => simulated.loseNextReply(),
			failover: () => simulated.failover(),
			restart: () => simulated.restart(),
			pressMemory: () => simulated.pressMemory(),
		};
	},
);
