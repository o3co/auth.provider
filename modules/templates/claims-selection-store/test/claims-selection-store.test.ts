import { selectionRecords } from "@mod/claims-selection";
import { selectionRecordsContract } from "@mod/claims-selection/testing";
import { assemble, type BuildContext, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

for (const phase of ["reader", "indexed"] as const) {
	selectionRecordsContract(
		`claims-selection-store on subject-records, on a simulated replicated store (${phase})`,
		async () => {
			const simulated = simulatedStore();
			if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
			const app = await assemble({
				modules: [simulated.module, wiring],
				config: kernelConfig(),
				runtime,
			});
			return {
				records: app.get(selectionRecords),
				advance: (ms: number) => simulated.shiftClock(ms),
				loseNextAnswer: () => simulated.loseNextReply(),
				failover: () => simulated.failover(),
				restart: () => simulated.restart(),
				pressMemory: () => simulated.pressMemory(),
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
