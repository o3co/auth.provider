import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { factorStore } from "@mod/mfa";
import { factorStoreContract } from "@mod/mfa/testing";
import { type Store, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
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
		raceNextTogether: (key, change) =>
			simulated.beforeNext("batchAcross", "mfa-store.factors", async () => {
				await factors.update(key, (record) => ({ value: change(record) }));
			}),
		duringNextSave: (during) => simulated.beforeConfirm("putIfAbsent", "mfa-store.factors", during),
		loseNextAnswer: () => simulated.loseNextReply(),
		failover: () => simulated.failover(),
		restart: () => simulated.restart(),
		pressMemory: () => simulated.pressMemory(),
	};
});

it("refuses to start over a store that writes no records of two partitions as one", async () => {
	const lacking = defineModule({ name: "lacking-store" }, (m) => [
		// Refused while it is built, before any call: a store with no batch across is enough.
		m.provide(store).by(() => ({}) as Store),
	]);
	const refused = await assemble({
		modules: [lacking, wiring],
		config: kernelConfig(),
		runtime,
	}).then(
		() => undefined,
		(error: unknown) => error,
	);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals).toContainEqual({
		where: "mfa-store",
		reason: "its store writes no records of two partitions as one",
	});
});
