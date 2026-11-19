import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	Unavailable,
} from "@mod/kernel";
import { expect, it } from "vitest";
import { checkedUpkeep } from "../../checks/checks.ts";
import { type Space, spaces, store, storeControl, storeUpkeep } from "../../contract.ts";
import { type MemoryData, memoryData, memoryProcess } from "../../memory/memory.ts";
import storeModule from "../../module.ts";
import { contractSpaces, type UpkeepProcess, upkeepContract } from "../../testing.ts";

const clock = { now: () => Date.now() };
const never = { expiry: { kind: "never" } } as const;
const durable = defineModule({ name: "durable-owner", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(spaces).by(() => ({ name: "kept", guarantees: ["durable"], subjectData: "none" })),
]);

/** The data each process of the upkeep contract opened, so another opens the same. */
const dataOf = new WeakMap<UpkeepProcess, MemoryData>();
/** What a process's next `alone()` is made to answer, set by `withholdLook` and `disturbRead`. */
const made = new WeakMap<UpkeepProcess, "withheld" | "disturbed">();
// Test-only: these overrides prove the suite's shape and that its cases are not vacuous; they say
// nothing of memory, which sees every process, so never withholds a look nor is disturbed.
const opened = (data: MemoryData, declared: readonly Space[], mayBuildUnderKey = false) => {
	const process = memoryProcess(data, declared, mayBuildUnderKey);
	const answered = process.upkeep.alone.bind(process.upkeep);
	const wrapped: UpkeepProcess = {
		...process,
		upkeep: {
			...process.upkeep,
			alone: async () => {
				const next = made.get(wrapped);
				made.delete(wrapped);
				if (next === "withheld") return { kind: "unchecked", reasons: ["look-withheld primary"] };
				if (next === "disturbed") throw new Unavailable("store");
				return answered();
			},
		},
	};
	dataOf.set(wrapped, data);
	return wrapped;
};
const dataFor = (process: UpkeepProcess) => dataOf.get(process) as MemoryData;
upkeepContract("memory", {
	start: async (declared) => opened(memoryData(clock), declared),
	another: async (process, declared) => opened(dataFor(process), declared),
	holds: async (process, key) =>
		dataFor(process).values.has(JSON.stringify([key.space.name, key.partition, key.name])),
	anotherMayBuildUnderKey: async (process, declared) => opened(dataFor(process), declared, true),
	looks: true,
	attach: async (process) => {
		const attached = memoryProcess(dataFor(process), []);
		return async () => attached.detach();
	},
	withholdLook: async (process) => {
		made.set(process, "withheld");
	},
	disturbRead: async (process) => {
		made.set(process, "disturbed");
	},
	configured: (process) => [dataFor(process).server],
});

it("counts no process whose start was refused, and none once detached, each change and read it makes then unavailable", async () => {
	const data = memoryData(clock);
	const first = memoryProcess(data, contractSpaces);
	await first.upkeep.enterMaintenance();
	expect(() => memoryProcess(data, contractSpaces)).toThrow();
	expect(await first.upkeep.alone?.()).toEqual({ kind: "alone" });
	const tool = memoryProcess(data, contractSpaces, true);
	expect(await first.upkeep.alone?.()).toEqual({ kind: "accompanied", count: 1 });
	tool.detach();
	expect(await first.upkeep.alone?.()).toEqual({ kind: "alone" });
	// A detached process is stopped: each change and read it makes, through any port, is unavailable.
	const space = contractSpaces[0] as Space;
	const key = { space, partition: "p", name: "k" };
	const { store: s, control: c, upkeep: u } = tool;
	const calls: (() => Promise<unknown>)[] = [
		() => s.get(key),
		() => (s.getMany as NonNullable<typeof s.getMany>)([key]),
		() => s.putIfAbsent(key, 1, never),
		() => s.replaceIf(key, "1", 1, never),
		() => s.removeIf(key, { version: "1" }, {}),
		() => s.take(key, {}),
		() => s.batch([], [{ key, put: 1, expiry: { kind: "never" } }], {}),
		() => s.count(key, { limit: 1, ms: 1000 }, {}),
		() => s.now(),
		() => s.scan(space),
		() => c.control(),
		() => u.mark("owner.mark", 1),
		() => u.require([space.name]),
		() => u.enterMaintenance(),
		() => u.leaveMaintenance(),
		() => u.kept(),
		() => u.retire("gone"),
		() => u.honours([]),
		() => u.sweep(space),
		() => (u.alone as () => Promise<unknown>)(),
	];
	for (const call of calls) await expect(call()).rejects.toSatisfy(isUnavailable);
	expect((await first.store.putIfAbsent(key, 1, never)).kind).toBe("written");
});

it("answers alone() unchecked, no-look-offered, where the implementation offers no way to look, and the implementation's own answer where it does", async () => {
	const { alone, ...withoutAlone } = memoryProcess(memoryData(clock), []).upkeep;
	expect(await checkedUpkeep(withoutAlone, []).alone()).toEqual({
		kind: "unchecked",
		reasons: ["no-look-offered"],
	});
	expect(await checkedUpkeep({ ...withoutAlone, alone }, []).alone()).toEqual({ kind: "alone" });
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

it("is taken by account erasure's wiring alone: another module taking it refuses boot", async () => {
	const taking = (name: string) =>
		defineModule({ name, replicaSafe: true, takes: [storeUpkeep] }, (m) => [
			m.provide(contract<object>(`${name}.takes`)).by(async (c) => {
				try {
					await c.get(storeUpkeep);
				} catch {}
				return {};
			}),
		]);
	const boot = (name: string) =>
		assemble({
			modules: [storeModule, durable, taking(name)],
			config: { ...kernelConfig(), store: { "accept-volatile": true } },
		});
	const refused = await boot("intruder").catch((error: unknown) => error);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals.map((r) => r.reason)).toContain(
		"store.upkeep is taken by account-erasure-store alone",
	);
	await expect(boot("account-erasure-store")).resolves.toBeDefined();
});

it("provides the store and its upkeep from one process, whose own maintenance leaves it writing", async () => {
	const app = await assemble({
		modules: [storeModule, durable],
		config: { ...kernelConfig(), store: { "accept-volatile": true } },
	});
	const { epoch } = await app.get(storeUpkeep).enterMaintenance();
	expect((await app.get(storeControl).control()).epoch).toBe(epoch);
	const key = {
		space: { name: "kept", guarantees: ["durable"], subjectData: "none" },
		partition: "p",
		name: "k",
	} as const;
	expect((await app.get(store).putIfAbsent(key, 1, never)).kind).toBe("written");
	expect((await app.get(storeUpkeep).kept()).map((s) => s.name)).toEqual(["kept"]);
});
