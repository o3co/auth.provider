import {
	assemble,
	BootRefused,
	type BuildContext,
	contract,
	defineModule,
	kernelConfig,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { factorStore, type StoredFactors } from "@mod/mfa";
import { factorStoreContract } from "@mod/mfa/testing";
import { type Store, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

/** The wiring on a simulated replicated store at a phase, with the build context to read readiness. */
async function opened(phase: "reader" | "indexed" = "reader", blip = false) {
	const simulated = simulatedStore();
	if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
	simulated.unreachable(blip);
	let context: BuildContext<unknown> | undefined;
	const asker = defineModule({ name: "asker", replicaSafe: false, takes: [] }, (m) => [
		m.provide(contract<object>("asker")).by((c) => {
			context = c;
			return {};
		}),
	]);
	const app = await assemble({
		modules: [simulated.module, wiring, asker],
		config: kernelConfig(),
		runtime,
	});
	const ready = () => context?.readinessReport(1000).then((r) => r.answer);
	return { simulated, app, ready };
}

for (const phase of ["reader", "indexed"] as const) {
	// A list's write in indexed records watches its subject's tombstone, or lists it: a batch across.
	const written = phase === "indexed" ? "batchAcross" : "batch";
	factorStoreContract(
		`mfa-store on subject-records, ${phase}, on a simulated replicated store`,
		async () => {
			const { simulated, app } = await opened(phase);
			const factors = app.get(factorStore);
			return {
				factors,
				advance: (ms) => simulated.shiftClock(ms),
				raceNextUpdate: (key, change) =>
					simulated.beforeNext(written, "mfa-store.factors", async () => {
						await factors.update(key, (record) => ({ value: change(record) }));
					}),
				duringNextSave: (during) => simulated.beforeConfirm(written, "mfa-store.factors", during),
				loseNextAnswer: () => simulated.loseNextReply(),
				failover: () => simulated.failover(),
				restart: () => simulated.restart(),
				pressMemory: () => simulated.pressMemory(),
			};
		},
	);
}

it("erases a subject's lists and claims, refusing a new one for the subject and leaving another's", async () => {
	const { app } = await opened("indexed");
	const factors = app.get(factorStore);
	const list = (n: number) => ({ n }) as unknown as StoredFactors;
	await factors.save("s-a", list(1), "endless", "alice");
	await factors.save("s-b", list(2), "endless", "bob");
	expect(await factors.erase?.("alice", new AbortController().signal)).toMatchObject({
		kind: "erased",
		removed: 1,
	});
	expect(await factors.read("s-a")).toBeUndefined();
	expect(await factors.save("s-a2", list(3), "endless", "alice")).toBe("erased");
	expect(await factors.read("s-b")).toEqual(list(2));
});

it("starts over a store's blip unready, out of traffic, and turns ready once the store answers", async () => {
	const { simulated, ready } = await opened("indexed", true);
	expect(await ready()).toBe("unready");
	simulated.unreachable(false);
	expect(await ready()).toBe("ready");
});

it("refuses to start over a store that writes no records of two partitions as one", async () => {
	const lacking = defineModule({ name: "lacking-store", replicaSafe: true, takes: [] }, (m) => [
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
