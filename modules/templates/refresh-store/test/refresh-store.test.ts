import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { crowdingFor } from "@mod/records/testing";
import {
	familyStore,
	issuedAccess,
	redemptionStore,
	sessionFamilies,
	settleList,
	tokenFamilies,
} from "@mod/refresh";
import { refreshStoreContract } from "@mod/refresh/testing";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

// Smaller than the defaults, and apart from each other, so each limit holds only if the section is read.
const caps = { sessionFamilies: 4, issuedAccess: 6 };
const settlesSize = { shards: 4, perShard: 3 };

// The kernel's clock; the simulated store's runs on it, shifted where a test says.
let now = 1_800_000_000_000;
const runtime = quietRuntime({ clock: { now: () => now } });

async function open() {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: {
			...kernelConfig(),
			"refresh-store": {
				"families-per-session": caps.sessionFamilies,
				"tokens-per-family": caps.issuedAccess,
				"settle-shards": settlesSize.shards,
				"settles-per-shard": settlesSize.perShard,
			},
		},
		runtime,
	});
	return { simulated, app };
}

refreshStoreContract("refresh-store on records, on a simulated replicated store", async () => {
	const { simulated, app } = await open();
	const families = app.get(familyStore);
	return {
		families,
		redemptions: app.get(redemptionStore),
		sessionFamilies: app.get(sessionFamilies),
		issuedAccess: app.get(issuedAccess),
		tokenFamilies: app.get(tokenFamilies),
		settles: app.get(settleList),
		caps,
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (id, change) =>
			simulated.beforeNext("replaceIf", "refresh-store.families", async () => {
				await families.update(id, (record) => ({ value: change(record) }));
			}),
		crowd: { limit: settlesSize.perShard, ids: crowdingFor(settlesSize).jobs },
		loseNextAnswer: () => simulated.loseNextReply(),
		failover: () => simulated.failover(),
		restart: () => simulated.restart(),
		pressMemory: () => simulated.pressMemory(),
	};
});

it("ends the members of its keyed sets on the kernel's clock, whatever the store's says", async () => {
	const { simulated, app } = await open();
	for (const sets of [app.get(sessionFamilies), app.get(issuedAccess)]) {
		await sets.add("k", "m", 1000);
		simulated.shiftClock(-60_000);
		now += 1500;
		expect(await sets.members("k")).toEqual([]);
		simulated.shiftClock(60_000);
	}
});
