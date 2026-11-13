import { approvalRecords, deviceStore, userCodes } from "@mod/device-grant";
import { deviceStoreContract } from "@mod/device-grant/testing";
import type { Walk } from "@mod/erasure-extensions";
import { assemble, type BuildContext, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Space, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

for (const phase of ["reader", "indexed"] as const) {
	deviceStoreContract(
		`device-grant-store on records and subject-records, on a simulated replicated store (${phase})`,
		async () => {
			const simulated = simulatedStore();
			if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
			const app = await assemble({
				modules: [simulated.module, wiring],
				config: kernelConfig(),
				runtime,
			});
			const devices = app.get(deviceStore);
			const inner = app.get(store);
			// The walk a maintenance tool hands in: the store's own scan, on one server.
			const walk: Walk = {
				sweep: async (space, cursor) => {
					const page = await inner.scan({ name: space, guarantees: [] } as Space, cursor);
					return page.cursor === undefined
						? { keys: page.keys, server: "one" }
						: { keys: page.keys, cursor: page.cursor, server: "one" };
				},
			};
			return {
				devices,
				userCodes: app.get(userCodes),
				approvals: app.get(approvalRecords),
				walkOf: () => walk,
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
		},
	);
}

it("starts over a store's blip unready, out of traffic, and turns ready once the store answers", async () => {
	const simulated = simulatedStore();
	simulated.mark("subject-records.phase", "indexed");
	simulated.unreachable(true);
	let context: BuildContext<unknown> | undefined;
	const asker = defineModule({ name: "asker", replicaSafe: false, takes: [] }, (m) => [
		m.provide(contract<object>("asker")).by((c) => {
			context = c;
			return {};
		}),
	]);
	await assemble({ modules: [simulated.module, wiring, asker], config: kernelConfig(), runtime });
	const ready = () => context?.readinessReport(1000).then((r) => r.answer);
	expect(await ready()).toBe("unready");
	simulated.unreachable(false);
	expect(await ready()).toBe("ready");
});
