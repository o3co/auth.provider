import { deviceStore, userCodes } from "@mod/device-grant";
import { deviceStoreContract } from "@mod/device-grant/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

deviceStoreContract("device-grant-store on records, on a simulated replicated store", async () => {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime,
	});
	const devices = app.get(deviceStore);
	return {
		devices,
		userCodes: app.get(userCodes),
		advance: (ms) => simulated.shiftClock(ms),
		raceNextUpdate: (hash, change) =>
			simulated.beforeNext("replaceIf", "device-grant-store.devices", async () => {
				await devices.update(hash, (record) => ({ value: change(record) }));
			}),
		loseNextAnswer: () => simulated.loseNextReply(),
		failover: () => simulated.failover(),
		restart: () => simulated.restart(),
		pressMemory: () => simulated.pressMemory(),
		holds: (text) => simulated.holds(text),
	};
});
