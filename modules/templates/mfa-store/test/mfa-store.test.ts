import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { factorStore } from "@mod/mfa";
import { factorStoreContract } from "@mod/mfa/testing";
import { simulatedStore } from "@mod/store/testing";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

factorStoreContract("mfa-store on records, on a simulated replicated store", async () => {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime,
	});
	const factors = app.get(factorStore);
	return {
		factors,
		advance: (ms) => simulated.shiftClock(ms),
		raceNextUpdate: (key, change) =>
			simulated.beforeNext("replaceIf", "mfa-store.factors", async () => {
				await factors.update(key, (record) => ({ value: change(record) }));
			}),
		duringNextSave: (during) => simulated.beforeConfirm("putIfAbsent", "mfa-store.factors", during),
		loseNextAnswer: () => simulated.loseNextReply(),
		failover: () => simulated.failover(),
		restart: () => simulated.restart(),
		pressMemory: () => simulated.pressMemory(),
	};
});
