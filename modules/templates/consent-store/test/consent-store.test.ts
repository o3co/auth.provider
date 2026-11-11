import { askStore, grantStore, type StoredAsk, type StoredGrant } from "@mod/consent";
import { askStoreContract, grantStoreContract } from "@mod/consent/testing";
import { assemble, type BuildContext, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

/** The wiring over a simulated store, its records in the phase given; and the composition's readiness. */
async function opened(phase: "reader" | "indexed" = "reader", blip = false) {
	const simulated = simulatedStore();
	if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
	simulated.unreachable(blip);
	let context: BuildContext<unknown> | undefined;
	const app = await assemble({
		modules: [
			simulated.module,
			wiring,
			defineModule({ name: "asker", replicaSafe: false, takes: [] }, (m) => [
				m.provide(contract<object>("asker")).by((c) => {
					context = c;
					return {};
				}),
			]),
		],
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
	const ready = () => context?.readinessReport(1000).then((r) => r.answer);
	return { app, simulated, faults, ready };
}

for (const phase of ["reader", "indexed"] as const) {
	// A grant's change in indexed records watches its subject's tombstone: a batch across.
	const grantWrite = phase === "indexed" ? "batchAcross" : "batch";
	grantStoreContract(
		`consent-store on subject-records, ${phase}, on a simulated replicated store`,
		async () => {
			const { app, simulated, faults } = await opened(phase);
			const records = app.get(grantStore);
			return {
				records,
				...faults,
				raceNextUpdate: (key, change) =>
					simulated.beforeNext(grantWrite, "consent-store.grants", async () => {
						await records.update(key, (record) => ({ value: change(record) }));
					}),
			};
		},
	);

	askStoreContract(
		`consent-store on subject-records, ${phase}, on a simulated replicated store`,
		async () => {
			const { app, simulated, faults } = await opened(phase);
			const records = app.get(askStore);
			return {
				records,
				...faults,
				holds: (text) => simulated.holds(text),
				// A bounded ask is kept raw, watching no tombstone: one partition.
				raceNextUpdate: (key, change) =>
					simulated.beforeNext("batch", "consent-store.asks", async () => {
						await records.update(key, (record) => ({ value: change(record) }));
					}),
			};
		},
	);
}

it("erases a subject's grants and fences its asks: a grant read none, an old ask changed until its end, no new one saved", async () => {
	const { app } = await opened("indexed");
	const grants = app.get(grantStore);
	const asks = app.get(askStore);
	const signal = new AbortController().signal;
	await grants.save("g", { range: ["read"] } as unknown as StoredGrant, "endless", "alice");
	await asks.save("a", { n: 1 } as unknown as StoredAsk, 60_000, "alice");
	expect(await grants.erase?.("alice", signal)).toMatchObject({ kind: "erased", removed: 1 });
	expect(await asks.erase?.("alice", signal)).toMatchObject({ kind: "fenced" });
	expect(await grants.read("g")).toBeUndefined();
	expect(await grants.save("g2", {} as StoredGrant, "endless", "alice")).toBe("erased");
	expect(await asks.save("a2", { n: 2 } as unknown as StoredAsk, 60_000, "alice")).toBe("erased");
	// An ask from before the erasure ends by its own end; consent grants nothing from it.
	expect(await asks.update("a", () => ({ value: { n: 3 } as unknown as StoredAsk }))).toMatchObject(
		{
			after: { n: 3 },
		},
	);
});

it("starts over a store's blip unready, out of traffic, and turns ready once the store answers", async () => {
	const { simulated, ready } = await opened("indexed", true);
	expect(await ready()).toBe("unready");
	simulated.unreachable(false);
	expect(await ready()).toBe("ready");
});
