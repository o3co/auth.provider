import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { heldLoginStore } from "@mod/upstream-handoff";
import { heldLoginStoreContract } from "@mod/upstream-handoff/testing";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

heldLoginStoreContract(
	"upstream-handoff-store on records, on a simulated replicated store",
	async () => {
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime,
		});
		const held = app.get(heldLoginStore);
		return {
			held,
			advance: (ms) => simulated.shiftClock(ms),
			raceNextUpdate: (name, change) =>
				simulated.beforeNext("replaceIf", "upstream-handoff-store.held-logins", async () => {
					await held.update(name, (record) => ({ value: change(record) }));
				}),
			loseNextAnswer: () => simulated.loseNextReply(),
			failover: () => simulated.failover(),
			holds: (text) => simulated.holds(text),
		};
	},
);
