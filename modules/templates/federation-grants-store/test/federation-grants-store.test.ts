import {
	grantStore,
	pendingIntents,
	refreshLockStore,
	stepStore,
	subjectGrants,
} from "@mod/federation-grants";
import { grantStoreContract, refreshLockStoreContract } from "@mod/federation-grants/testing";
import { assemble, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";
import { section } from "../src/section.ts";

grantStoreContract(
	"federation-grants-store on records, on a simulated replicated store",
	async () => {
		let now = 1_800_000_000_000;
		const runtime = quietRuntime({ clock: { now: () => now } });
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: {
				...kernelConfig(),
				"federation-grants-store": { "pending-per-client-and-subject": 3 },
			},
			runtime,
		});
		const grants = app.get(grantStore);
		return {
			grants,
			steps: app.get(stepStore),
			pending: app.get(pendingIntents),
			subjects: app.get(subjectGrants),
			cap: 3,
			// The simulated store reads the composition's clock, as keyed sets do.
			advance: (ms) => {
				now += ms;
			},
			raceNextChange: (id, change) =>
				simulated.beforeNext("replaceIf", "federation-grants-store.grants", async () => {
					await grants.change(id, (record) => ({ value: change(record) }));
				}),
			failover: () => simulated.failover(),
			duringNextCreate: (during) =>
				simulated.beforeConfirm("putIfAbsent", "federation-grants-store.grants", during),
			restart: () => simulated.restart(),
			pressMemory: () => simulated.pressMemory(),
			holds: (text) => simulated.holds(text),
		};
	},
);

refreshLockStoreContract(
	"federation-grants-store on records, on a simulated replicated store",
	async () => {
		let now = 1_800_000_000_000;
		const runtime = quietRuntime({ clock: { now: () => now } });
		const simulated = simulatedStore();
		const app = await assemble({
			modules: [simulated.module, wiring],
			config: kernelConfig(),
			runtime,
		});
		return {
			locks: app.get(refreshLockStore),
			advance: (ms) => {
				now += ms;
			},
			pressMemory: () => simulated.pressMemory(),
		};
	},
);

it("keeps 16 intents waiting to a pair unless told otherwise, from 1 to 1000", () => {
	expect(section.parse({})).toMatchObject({ "pending-per-client-and-subject": 16 });
	for (const bad of [0, 1001, 1.5]) {
		expect(section.safeParse({ "pending-per-client-and-subject": bad }).success).toBe(false);
	}
	// The cap counts per client and subject; the name that said per subject is refused, not ignored.
	expect(section.safeParse({ "pending-per-subject": 3 }).success).toBe(false);
});

it("lists 100 grants a subject unless told otherwise, from 1 to 10000", () => {
	expect(section.parse({})).toMatchObject({ "grants-per-subject": 100 });
	for (const bad of [0, 10_001, 1.5]) {
		expect(section.safeParse({ "grants-per-subject": bad }).success).toBe(false);
	}
	expect(section.parse({ "grants-per-subject": 10_000 })).toBeDefined();
});
