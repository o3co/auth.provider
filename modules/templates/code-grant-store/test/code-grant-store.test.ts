import {
	codeStore,
	redemptionRecords,
	type StoredCode,
	type StoredRedemptionRecord,
	storedRecordMaxMs,
	voidList,
} from "@mod/code-grant";
import { codeStoreContract } from "@mod/code-grant/testing";
import { assemble, type BuildContext, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { crowdingFor } from "@mod/records/testing";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import wiring from "../src/module.ts";

// Smaller than the defaults, so a full shard is reached only if the section is read.
const voidsSize = { shards: 4, perShard: 3 };

const runtime = quietRuntime({ clock: { now: () => 1_800_000_000_000 } });

for (const phase of ["reader", "indexed"] as const) {
	codeStoreContract(
		`code-grant-store on subject-records, on a simulated replicated store (${phase})`,
		async () => {
			const simulated = simulatedStore();
			if (phase === "indexed") simulated.mark("subject-records.phase", "indexed");
			const app = await assemble({
				modules: [simulated.module, wiring],
				config: {
					...kernelConfig(),
					"code-grant-store": {
						"void-shards": voidsSize.shards,
						"voids-per-shard": voidsSize.perShard,
					},
				},
				runtime,
			});
			const codes = app.get(codeStore);
			return {
				codes,
				voids: app.get(voidList),
				redemptionRecords: app.get(redemptionRecords),
				advance: (ms) => simulated.shiftClock(ms),
				raceNextUpdate: (hash, change) =>
					simulated.beforeNext("batch", "code-grant-store.codes", async () => {
						await codes.update(hash, (record) => ({ value: change(record) }));
					}),
				crowd: { limit: voidsSize.perShard, names: crowdingFor(voidsSize).jobs },
				loseNextAnswer: () => simulated.loseNextReply(),
				failover: () => simulated.failover(),
				restart: () => simulated.restart(),
				pressMemory: () => simulated.pressMemory(),
				holds: (text) => simulated.holds(text),
			};
		},
	);
}

it("creates a code by the code, under the name records make of it, once", async () => {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime,
	});
	const codes = app.get(codeStore);
	const record = { n: 1 } as unknown as StoredCode;
	expect(await codes.create("the-code", record, 60_000, "alice")).toBe("created");
	expect(await codes.create("the-code", record, 60_000, "alice")).toBe("exists");
	expect((await codes.update(codes.nameOf("the-code"), () => undefined))?.after).toEqual(record);
});

/** The wiring on a simulated store, its records raw (`reader`) or indexed, unreachable at first where `blip`. */
async function opened(phase: "reader" | "indexed", blip = false) {
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
	return { simulated, ready, records: app.get(redemptionRecords), codes: app.get(codeStore) };
}

const record = (n: number) => ({ n }) as unknown as StoredRedemptionRecord;
const code = (n: number) => ({ n }) as unknown as StoredCode;

for (const phase of ["reader", "indexed"] as const) {
	it(`keeps a redemption record once by its name, for its subject, and changes it only from what it holds (${phase})`, async () => {
		const { records } = await opened(phase);
		expect(await records.create("r1", record(1), 60_000, "alice")).toBe("created");
		expect(await records.create("r1", record(2), 60_000, "alice")).toBe("exists");
		expect(await records.read("r1")).toEqual(record(1));
		expect(await records.update("r1", () => ({ value: record(3) }))).toEqual({
			before: record(1),
			after: record(3),
		});
		expect(await records.update("none", () => ({ value: record(4) }))).toBeUndefined();
		// Bounded past the longest token and its allowances, never longer.
		await expect(records.create("r2", record(1), storedRecordMaxMs + 1, "alice")).rejects.toThrow(
			TypeError,
		);
	});
}

it("fences a redemption record's or a code's creation for an erased subject, leaving one kept to change until its end", async () => {
	const { records, codes } = await opened("indexed");
	const signal = new AbortController().signal;
	expect(await records.create("r1", record(1), 60_000, "alice")).toBe("created");
	expect(await codes.create("c1", code(1), 60_000, "alice")).toBe("created");
	for (const erase of [records.erase, codes.erase]) {
		expect(await erase?.("alice", signal)).toMatchObject({ kind: "fenced" });
	}
	expect(await records.create("r2", record(2), 60_000, "alice")).toBe("erased");
	expect(await codes.create("c2", code(2), 60_000, "alice")).toBe("erased");
	// A void after the erasure still lands, so a reuse revokes until the record's end.
	expect((await records.update("r1", () => ({ value: record(5) })))?.after).toEqual(record(5));
	expect((await codes.update(codes.nameOf("c1"), () => ({ value: code(5) })))?.after).toEqual(
		code(5),
	);
	expect(await records.create("r3", record(3), 60_000, "bob")).toBe("created");
});

it("starts over a store's blip unready, out of traffic, and turns ready once the store answers", async () => {
	const { simulated, ready } = await opened("indexed", true);
	expect(await ready()).toBe("unready");
	simulated.unreachable(false);
	expect(await ready()).toBe("ready");
});
