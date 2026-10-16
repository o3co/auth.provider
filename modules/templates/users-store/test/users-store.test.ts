import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { contactStore, linkStore } from "@mod/users";
import { contactStoreContract, linkStoreContract } from "@mod/users/testing";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

async function opened() {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime,
	});
	const faults = {
		advance: (ms: number) => simulated.shiftClock(ms),
		loseNextAnswer: () => simulated.loseNextReply(),
		failover: () => simulated.failover(),
		restart: () => simulated.restart(),
		pressMemory: () => simulated.pressMemory(),
		stallReplicas: (on: boolean) => simulated.stallReplicas(on),
	};
	return { app, simulated, faults };
}

linkStoreContract("users-store on records, on a simulated replicated store", async () => {
	const { app, simulated, faults } = await opened();
	const records = app.get(linkStore);
	return {
		records,
		...faults,
		raceNextUpdate: (key, change) =>
			simulated.beforeNext("replaceIf", "users-store.links", async () => {
				await records.update(key, (record) => ({ value: change(record) }));
			}),
	};
});

contactStoreContract("users-store on records, on a simulated replicated store", async () => {
	const { app, simulated, faults } = await opened();
	const records = app.get(contactStore);
	return {
		records,
		...faults,
		raceNextUpdate: (key, change) =>
			simulated.beforeNext("replaceIf", "users-store.contacts", async () => {
				await records.update(key, (record) => ({ value: change(record) }));
			}),
	};
});
