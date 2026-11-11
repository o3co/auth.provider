import { assemble, type BuildContext, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { crowdingFor } from "@mod/records/testing";
import {
	familyStore,
	issuedAccess,
	redemptionStore,
	type StoredFamily,
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

async function open(phase: "reader" | "indexed" = "reader", blip = false) {
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
	const ready = () => context?.readinessReport(1000).then((r) => r.answer);
	return { simulated, app, ready };
}

for (const phase of ["reader", "indexed"] as const) {
	// A family's change in indexed records watches its subject's tombstone: a batch across.
	const familyWrite = phase === "indexed" ? "batchAcross" : "batch";
	refreshStoreContract(
		`refresh-store on subject-records, ${phase}, on a simulated replicated store`,
		async () => {
			const { simulated, app } = await open(phase);
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
					simulated.beforeNext(familyWrite, "refresh-store.families", async () => {
						await families.update(id, (record) => ({ value: change(record) }));
					}),
				crowd: { limit: settlesSize.perShard, ids: crowdingFor(settlesSize).jobs },
				loseNextAnswer: () => simulated.loseNextReply(),
				failover: () => simulated.failover(),
				restart: () => simulated.restart(),
				pressMemory: () => simulated.pressMemory(),
			};
		},
	);
}

it("erases a subject's families, refusing a new one for the subject and leaving another's", async () => {
	const { app } = await open("indexed");
	const families = app.get(familyStore);
	const family = (n: number) => ({ n }) as unknown as StoredFamily;
	await families.save("f1", family(1), 60_000, "alice");
	await families.save("f2", family(2), 60_000, "bob");
	expect(await families.erase?.("alice", new AbortController().signal)).toMatchObject({
		kind: "erased",
		removed: 1,
	});
	expect(await families.read("f1")).toBeUndefined();
	expect(await families.save("f3", family(3), 60_000, "alice")).toBe("erased");
	expect(await families.read("f2")).toEqual({ n: 2 });
});

it("keeps a revoked mark with no record through unowned while records are raw, and marks nothing once indexed", async () => {
	const mark = { format: 1, revoked: true } as unknown as StoredFamily;
	const raw = (await open("reader")).app.get(familyStore);
	expect(await raw.unowned?.("f", mark, 60_000)).toBe("created");
	expect(await raw.read("f")).toEqual(mark);
	const indexed = (await open("indexed")).app.get(familyStore);
	expect(await indexed.unowned?.("f", mark, 60_000)).toBe("closed");
	expect(await indexed.read("f")).toBeUndefined();
});

it("starts over a store's blip unready, out of traffic, and turns ready once the store answers", async () => {
	const { simulated, ready } = await open("indexed", true);
	expect(await ready()).toBe("unready");
	simulated.unreachable(false);
	expect(await ready()).toBe("ready");
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
