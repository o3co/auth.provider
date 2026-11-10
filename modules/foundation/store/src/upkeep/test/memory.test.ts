import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { expect, it } from "vitest";
import { type Space, spaces, store, storeControl, storeUpkeep } from "../../contract.ts";
import { type MemoryData, memoryData, memoryProcess } from "../../memory.ts";
import storeModule from "../../module.ts";
import { contractSpaces, type UpkeepProcess, upkeepContract } from "../../testing.ts";

const clock = { now: () => Date.now() };
const never = { expiry: { kind: "never" } } as const;
const durable = defineModule({ name: "durable-owner", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(spaces).by(() => ({ name: "kept", guarantees: ["durable"] })),
]);

/** The data each process of the upkeep contract opened, so another opens the same. */
const dataOf = new WeakMap<UpkeepProcess, MemoryData>();
const opened = (data: MemoryData, declared: readonly Space[]) => {
	const process = memoryProcess(data, declared);
	dataOf.set(process, data);
	return process;
};
const dataFor = (process: UpkeepProcess) => dataOf.get(process) as MemoryData;
upkeepContract("memory", {
	start: async (declared) => opened(memoryData(clock), declared),
	another: async (process, declared) => opened(dataFor(process), declared),
	holds: async (process, key) =>
		dataFor(process).values.has(JSON.stringify([key.space.name, key.partition, key.name])),
});

it("answers durable and replicated unmet, and the rest verified, as one process holds them", async () => {
	const { upkeep } = memoryProcess(memoryData(clock), contractSpaces);
	expect(await upkeep.honours(["no-eviction", "confirmed-reads"])).toEqual({
		kind: "verified",
		witness: expect.any(String),
	});
	expect(await upkeep.honours(["no-eviction", "durable", "replicated"])).toEqual({
		kind: "unmet",
		reasons: ["memory loses everything on restart", "memory has no replica"],
	});
});

it("provides the store and its upkeep from one process, whose own maintenance leaves it writing", async () => {
	const app = await assemble({
		modules: [storeModule, durable],
		config: { ...kernelConfig(), store: { "accept-volatile": true } },
	});
	const { epoch } = await app.get(storeUpkeep).enterMaintenance();
	expect((await app.get(storeControl).control()).epoch).toBe(epoch);
	const key = {
		space: { name: "kept", guarantees: ["durable"] },
		partition: "p",
		name: "k",
	} as const;
	expect((await app.get(store).putIfAbsent(key, 1, never)).kind).toBe("written");
	expect((await app.get(storeUpkeep).kept()).map((s) => s.name)).toEqual(["kept"]);
});
