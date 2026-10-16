import { reauthStore } from "@mod/authorize";
import { reauthStoreContract } from "@mod/authorize/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

reauthStoreContract("authorize-store on records, on a simulated replicated store", async () => {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime,
	});
	const reauths = app.get(reauthStore);
	return {
		reauths,
		advance: (ms) => simulated.shiftClock(ms),
		raceNextUpdate: (name, change) =>
			simulated.beforeNext("replaceIf", "authorize-store.reauths", async () => {
				await reauths.update(name, (record) => ({ value: change(record) }));
			}),
		loseNextAnswer: () => simulated.loseNextReply(),
		failover: () => simulated.failover(),
		restart: () => simulated.restart(),
		holds: (text) => simulated.holds(text),
	};
});
