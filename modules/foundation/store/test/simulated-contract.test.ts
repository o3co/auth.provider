import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { spaces, store } from "../src/contract.ts";
import {
	contractSpaces,
	type SimulatedStore,
	simulatedStore,
	storeContract,
} from "../src/testing.ts";

let current: SimulatedStore | undefined;
const owner = defineModule({ name: "contract", takes: [] }, (m) =>
	contractSpaces.map((space) => m.contribute(spaces).by(() => space)),
);

storeContract("simulated", {
	open: async () => {
		current = simulatedStore();
		const app = await assemble({
			modules: [current.module, owner],
			config: kernelConfig(),
			runtime: quietRuntime(),
		});
		return app.get(store);
	},
	peer: async (s) => s,
	stopReplicas: async () => {
		current?.stallReplicas(true);
		return async () => current?.stallReplicas(false);
	},
	loseNextReply: async () => current?.loseNextReply(),
	restart: async () => current?.restart(),
	failover: async () => {
		await current?.failover();
		return async () => {};
	},
});
