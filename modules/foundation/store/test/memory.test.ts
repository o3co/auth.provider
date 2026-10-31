import {
	assemble,
	BootRefused,
	defineModule,
	type KernelSettings,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { type Space, spaces, store } from "../src/contract.ts";
import { memoryStore } from "../src/memory.ts";
import storeModule from "../src/module.ts";
import { contractSpaces, overwrite, storeContract } from "../src/testing.ts";

storeContract("memory", {
	open: async () => memoryStore({ now: () => Date.now() }, contractSpaces),
	peer: async (s) => s,
});

it("offers a batch across partitions and spaces of one guarantee, so the contract's batches across run on it", () => {
	expect(typeof memoryStore({ now: () => Date.now() }, contractSpaces).batchAcross).toBe(
		"function",
	);
});

it("judges the guarantees a batch across joins as sets, so a guarantee named twice changes nothing", async () => {
	const once: Space = { name: "once", guarantees: ["durable"] };
	const twice: Space = { name: "twice", guarantees: ["durable", "durable"] };
	const s = memoryStore({ now: () => Date.now() }, [once, twice]);
	const put = (space: Space) =>
		({
			key: { space, partition: space.name, name: "k" },
			put: 1,
			expiry: { kind: "never" },
		}) as const;
	expect((await s.batchAcross?.([], [put(once), put(twice)]))?.kind).toBe("committed");
});

// A store clock far from the caller's catches implementations that judge time by the caller's clock.
const skewed = { now: () => Date.now() + 3_600_000 };
storeContract("memory with a skewed store clock", {
	open: async () => memoryStore(skewed, contractSpaces),
	peer: async (s) => s,
});

const start = 1_800_000_000_000;
const never = { expiry: { kind: "never" } } as const;

/** A memory store on a clock the test moves by hand. */
function controlled() {
	const clock = { now: start };
	const s = memoryStore({ now: () => clock.now }, contractSpaces);
	const key = (name: string) => ({ space: contractSpaces[0] as Space, partition: "p", name });
	return { clock, s, key };
}

it("answers a resend of a write refused as late with late, even after the store clock goes back", async () => {
	const { clock, s, key } = controlled();
	const options = { ...never, deadline: start - 10, idempotency: "m" };
	expect((await s.putIfAbsent(key("a"), 1, options)).kind).toBe("late");
	clock.now -= 100;
	expect((await s.putIfAbsent(key("a"), 1, options)).kind).toBe("late");
	expect((await s.get(key("a"))).entry).toBeNull();
	expect((await s.putIfAbsent(key("a"), 2, options)).kind).toBe("reused");
});

it("takes a write at its deadline and refuses it just after", async () => {
	const { s, key } = controlled();
	expect((await s.putIfAbsent(key("a"), 1, { ...never, deadline: start })).kind).toBe("written");
	expect((await s.putIfAbsent(key("a"), 1, { ...never, deadline: start - 1 })).kind).toBe("late");
});

it("forgets a mark exactly one second after its deadline, or five minutes and a second after", async () => {
	const { clock, s, key } = controlled();
	await s.putIfAbsent(key("a"), 1, { ...never, deadline: start, idempotency: "d" });
	await s.putIfAbsent(key("a"), 1, { ...never, idempotency: "n" });
	clock.now = start + 999;
	expect((await s.putIfAbsent(key("a"), 2, { ...never, idempotency: "d" })).kind).toBe("reused");
	clock.now = start + 1000;
	expect((await s.putIfAbsent(key("a"), 2, { ...never, idempotency: "d" })).kind).toBe("exists");
	clock.now = start + 300_999;
	expect((await s.putIfAbsent(key("a"), 2, { ...never, idempotency: "n" })).kind).toBe("reused");
	clock.now = start + 301_000;
	expect((await s.putIfAbsent(key("a"), 2, { ...never, idempotency: "n" })).kind).toBe("exists");
});

it("keeps no mark for a batch that names no key", async () => {
	const { s } = controlled();
	expect((await s.batch([], [], { deadline: start - 1, idempotency: "m" })).kind).toBe("late");
	expect((await s.batch([], [], { deadline: start + 1, idempotency: "m" })).kind).toBe("committed");
});

it("keeps marks and counts through the periodic sweep of what has expired", async () => {
	const { s, key } = controlled();
	const first = await s.putIfAbsent(key("a"), 1, { ...never, idempotency: "m" });
	await s.count(key("hits"), { ms: 60_000, limit: 10 });
	for (let i = 0; i < 300; i++) await overwrite(s, key("other"), i, never);
	expect(await s.putIfAbsent(key("a"), 1, { ...never, idempotency: "m" })).toEqual(first);
	expect(await s.count(key("hits"), { ms: 60_000, limit: 10 })).toMatchObject({ count: 2 });
});

it("answers frozen, so a caller cannot change the answer a resend gets", async () => {
	const { s, key } = controlled();
	const first = await s.putIfAbsent(key("a"), 1, { ...never, idempotency: "m" });
	expect(() => Object.assign(first, { version: "changed" })).toThrow(TypeError);
	expect((await s.putIfAbsent(key("a"), 1, { ...never, idempotency: "m" })).kind).toBe("written");
});

it("never shortens an expiry when asked to extend it", async () => {
	const { clock, s, key } = controlled();
	await overwrite(s, key("a"), 1, { expiry: { kind: "after", ms: 10_000 } });
	await overwrite(s, key("a"), 2, { expiry: { kind: "extend", ms: 100 } });
	clock.now = start + 5000;
	expect((await s.get(key("a"))).entry?.value).toBe(2);
});

it("tells no remaining time for an entry that never expires", async () => {
	const { s, key } = controlled();
	await overwrite(s, key("a"), 1, never);
	expect(await s.putIfAbsent(key("a"), 2, never)).toEqual({ kind: "exists", remainingMs: null });
});

it("removes on a version only when it is the entry's version", async () => {
	const { s, key } = controlled();
	const written = await overwrite(s, key("a"), 1, never);
	const version = written.kind === "written" ? written.version : "";
	expect((await s.removeIf(key("a"), { version: `${version}x` })).kind).toBe("conflict");
	expect((await s.removeIf(key("a"), { version })).kind).toBe("removed");
});

it("refuses a batch whose key must be absent but is present", async () => {
	const { s, key } = controlled();
	await overwrite(s, key("a"), 1, never);
	const absent = [{ key: key("a"), absent: true as const }];
	expect(await s.batch(absent, [{ key: key("a"), remove: true }])).toEqual({
		kind: "conflict",
		index: 0,
	});
	expect((await s.get(key("a"))).entry?.value).toBe(1);
});

it("starts a new window at its reset time, and refuses every hit under a limit of zero", async () => {
	const { clock, s, key } = controlled();
	await s.count(key("hits"), { ms: 1000, limit: 1 });
	clock.now = start + 1000;
	expect(await s.count(key("hits"), { ms: 1000, limit: 1 })).toMatchObject({ kind: "counted" });
	expect(await s.count(key("zero"), { ms: 1000, limit: 0 })).toMatchObject({ kind: "limited" });
	expect(await s.count(key("zero"), { ms: 1000, limit: 1 })).toMatchObject({ count: 1 });
});

const durable = defineModule({ name: "durable-owner", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(spaces).by(() => ({ name: "kept", guarantees: ["durable"] })),
]);
const replicated = defineModule({ name: "replicated-owner", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(spaces).by(() => ({ name: "copied", guarantees: ["replicated"] })),
]);

it("refuses durable or replicated spaces unless volatility is accepted, and is unsafe on many replicas", async () => {
	const config = (accept: boolean, deployment: KernelSettings["deployment"] = "single") => ({
		...kernelConfig({ deployment }),
		store: { "accept-volatile": accept },
	});
	await expect(
		assemble({ modules: [storeModule, durable], config: config(false) }),
	).rejects.toBeInstanceOf(BootRefused);
	await expect(
		assemble({ modules: [storeModule, replicated], config: config(false) }),
	).rejects.toBeInstanceOf(BootRefused);
	const app = await assemble({ modules: [storeModule, durable], config: config(true) });
	expect(app.get(store)).toBeDefined();
	await expect(
		assemble({ modules: [storeModule], config: config(true, "multi") }),
	).rejects.toBeInstanceOf(BootRefused);
});

it("warns at every start that boots durable or replicated spaces on memory, naming them", async () => {
	const warned = async (...owners: Module[]) => {
		const recorded = recordingLog();
		await assemble({
			modules: [storeModule, ...owners],
			config: { ...kernelConfig(), store: { "accept-volatile": true } },
			runtime: quietRuntime({ log: recorded.log }),
		});
		return recorded.lines().filter((line) => line.level === "warn");
	};
	expect(await warned(durable, replicated)).toEqual([
		{ level: "warn", event: "store.volatile_accepted", fields: { spaces: "kept,copied" } },
	]);
	expect(await warned()).toEqual([]);
});
