import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { roundTripStore } from "@mod/upstream-round-trip";
import { roundTripStoreContract } from "@mod/upstream-round-trip/testing";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

roundTripStoreContract(
	"upstream-round-trip-store on records, on a simulated replicated store",
	async () => {
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime,
		});
		const roundTrips = app.get(roundTripStore);
		return {
			roundTrips,
			advance: (ms) => simulated.shiftClock(ms),
			raceNextUpdate: (name, change) =>
				simulated.beforeNext("replaceIf", "upstream-round-trip-store.round-trips", async () => {
					await roundTrips.update(name, (record) => ({ value: change(record) }));
				}),
			loseNextAnswer: () => simulated.loseNextReply(),
			failover: () => simulated.failover(),
			holds: (text) => simulated.holds(text),
		};
	},
);
