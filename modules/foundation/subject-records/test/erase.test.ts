import { createHash, randomBytes } from "node:crypto";
import { assemble, contract, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Control, type Json, type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import {
	eraseSubject,
	indexSpaceOf,
	subjectKeyedSetsIn,
	subjectRecordsIn,
	subjectRecordsPhase,
	sweepIndex,
} from "../src/subject-records.ts";

const g = ["durable"] as const;
const indexed: Space = { name: "erased-test", guarantees: g, subjectData: "online-indexed" };
const keyed: Space = { name: "erased-keyed", guarantees: g, subjectData: "online-keyed" };
const bounded: Space = {
	name: "erased-bounded",
	guarantees: g,
	subjectData: "bounded",
	boundedMs: 60_000,
};
const held = contract<Store>("test.store");
const refuse = (where: string, reason: string): never => {
	throw new Error(`${where}: ${reason}`);
};
const clock = { now: () => Date.now() };
const random = { bytes: (n: number) => new Uint8Array(randomBytes(n)) };
const part = (space: Space, subject: string) =>
	`1.${createHash("sha256").update(`${space.name}\n${subject}`).digest("base64url")}`;
const bucketOf = (key: string) => `m${createHash("sha256").update(key).digest("hex")[0]}`;

async function opened() {
	const app = await assemble({
		modules: [
			simulatedStore().module,
			defineModule({ name: "user", replicaSafe: false, takes: [store] }, (m) => [
				...[indexed, keyed, bounded].flatMap((space) => [
					m.contribute(spaces).by(() => space),
					m.contribute(spaces).by(() => indexSpaceOf(space)),
				]),
				m.provide(held).by((c) => c.get(store)),
			]),
		],
		config: kernelConfig(),
		runtime: quietRuntime(),
	});
	const s = app.get(held);
	const at = (space: Space, over: Store = s, phase: "reader" | "indexed" = "indexed") => ({
		store: over,
		space,
		index: indexSpaceOf(space),
		random,
		phase,
	});
	/** What a subject's part of the index holds, by name after the part. */
	const indexOf = async (space: Space, subject: string) => {
		const found: Record<string, Json> = {};
		let cursor: string | undefined;
		do {
			const page = await s.scan(indexSpaceOf(space), cursor);
			for (const k of page.keys) {
				if (k.name === "record" && k.partition.startsWith(`${part(space, subject)}.`)) {
					found[k.partition.slice(part(space, subject).length + 1)] = (await s.get(k)).entry
						?.value as Json;
				}
			}
			cursor = page.cursor;
		} while (cursor !== undefined);
		return found;
	};
	/** Lists keys in a subject's buckets as an index would hold them, with no records written. */
	const listed = async (space: Space, subject: string, keys: readonly string[]) => {
		for (const bucket of new Set(keys.map(bucketOf))) {
			const key = {
				space: indexSpaceOf(space),
				partition: `${part(space, subject)}.${bucket}`,
				name: "record",
			};
			await s.putIfAbsent(key, keys.filter((k) => bucketOf(k) === bucket).sort(), {
				expiry: { kind: "never" },
			});
		}
	};
	const raw = async (space: Space, partition: string, name = "record") =>
		(await s.get({ space, partition, name })).entry?.value;
	return { s, at, indexOf, listed, raw };
}

const control = (maintenance: boolean, phase?: string): Control => ({
	epoch: "e2",
	maintenance,
	requires: [],
	marks: phase === undefined ? {} : { "subject-records.phase": { value: phase, epoch: "e1" } },
});

it("reads the phase from its mark in any epoch, and tells the mark to write only under maintenance, never back to reader", async () => {
	const read = (c: Control) => subjectRecordsPhase.read({ control: async () => c });
	expect(await read(control(false))).toBe("reader");
	expect(await read(control(false, "indexed"))).toBe("indexed");
	expect(await read(control(false, "other"))).toBe("reader");
	expect(subjectRecordsPhase.write(control(false), "indexed")).toEqual({
		kind: "not-in-maintenance",
	});
	expect(subjectRecordsPhase.write(control(true), "indexed")).toEqual({
		kind: "write",
		name: "subject-records.phase",
		value: "indexed",
	});
	expect(subjectRecordsPhase.write(control(true, "indexed"), "reader")).toEqual({
		kind: "stays-indexed",
	});
});

it("erases a subject's records and sets its index lists, past a tombstone no create crosses, leaving another's", async () => {
	const { at, indexOf, raw } = await opened();
	const records = subjectRecordsIn<number>(at(indexed), "w", refuse);
	const sets = subjectKeyedSetsIn({ ...at(indexed), cap: 5, clock }, "w", refuse);
	const keys = Array.from({ length: 40 }, (_, i) => `a${i}`);
	for (const key of keys) await records.create(key, "alice", 1, 60_000);
	await sets.add("grp", "alice", "m", 60_000);
	await records.create("b", "bob", 2, 60_000);
	expect(await eraseSubject(at(indexed), "alice")).toEqual({
		kind: "erased",
		space: indexed.name,
		removed: 41,
	});
	expect(Object.keys(await indexOf(indexed, "alice"))).toEqual(["tomb"]);
	expect(await raw(indexed, "a0")).toBeUndefined();
	expect(await raw(indexed, "grp", "set")).toBeUndefined();
	expect(await records.read("b")).toBe(2);
	expect(await records.create("again", "alice", 1, 60_000)).toBe("erased");
	expect(await eraseSubject(at(indexed), "alice")).toMatchObject({ kind: "erased", removed: 0 });
});

it("leaves another subject's record created at a listed key between the erase's read and its write", async () => {
	const { s, at, listed, indexOf, raw } = await opened();
	await listed(indexed, "alice", ["k"]);
	const bobs = subjectRecordsIn<number>(at(indexed), "w", refuse);
	let raced = false;
	const racing = new Proxy(s, {
		get(target, name) {
			if (name === "batchAcross") {
				return async (...args: Parameters<NonNullable<Store["batchAcross"]>>) => {
					const removesK = args[1].some((w) => w.key.partition === "k" && "remove" in w);
					if (removesK && !raced) {
						raced = true;
						expect(await bobs.create("k", "bob", 7, 60_000)).toBe("created");
					}
					return target.batchAcross?.(...args);
				};
			}
			const value = Reflect.get(target, name);
			return typeof value === "function" ? value.bind(target) : value;
		},
	});
	expect(await eraseSubject(at(indexed, racing), "alice")).toMatchObject({
		kind: "erased",
		removed: 0,
	});
	expect(raced).toBe(true);
	expect(await raw(indexed, "k")).toEqual({ "records:v": 1, subject: "bob", value: 7 });
	expect(Object.keys(await indexOf(indexed, "alice"))).toEqual(["tomb"]);
	expect(await indexOf(indexed, "bob")).toEqual({ [bucketOf("k")]: ["k"] });
});

it("erases a subject keyed by its subject under the keys its owner makes, and takes keys there alone", async () => {
	const { at, raw } = await opened();
	const records = subjectRecordsIn<number>(at(keyed), "w", refuse);
	const sets = subjectKeyedSetsIn({ ...at(keyed), cap: 5, clock }, "w", refuse);
	await records.create("u:alice", "alice", 1, "endless");
	await sets.add("u:alice", "alice", "m", 60_000);
	expect(await eraseSubject(at(keyed), "alice", { keys: ["u:alice"] })).toMatchObject({
		kind: "erased",
		removed: 2,
	});
	expect(await raw(keyed, "u:alice")).toBeUndefined();
	expect(await records.create("u:alice", "alice", 1, "endless")).toBe("erased");
	await expect(eraseSubject(at(keyed), "alice")).rejects.toThrow(TypeError);
	await expect(eraseSubject(at(indexed), "alice", { keys: [] })).rejects.toThrow(TypeError);
});

it("fences a bounded space until its tombstone's deadline and the space's ceiling, the same on every run", async () => {
	const { at } = await opened();
	const before = Date.now();
	const first = await eraseSubject(at(bounded), "alice");
	expect(first.kind).toBe("fenced");
	const until = (first as { until: number }).until;
	expect(until).toBeGreaterThanOrEqual(before + 60_000);
	expect(until).toBeLessThanOrEqual(Date.now() + 60_000 + 60_000);
	expect(await eraseSubject(at(bounded), "alice")).toEqual(first);
	const records = subjectRecordsIn<number>(at(bounded), "w", refuse);
	expect(await records.create("k", "alice", 1, 1_000)).toBe("erased");
});

it("stops where records are not indexed, where it is aborted with its tombstone standing, and where the store is unavailable", async () => {
	const { s, at } = await opened();
	expect(await eraseSubject(at(indexed, s, "reader"), "alice")).toMatchObject({
		kind: "stopped",
		reason: "not-indexed",
	});
	const records = subjectRecordsIn<number>(at(indexed), "w", refuse);
	await records.create("a", "alice", 1, 60_000);
	const aborted = new AbortController();
	const stopping = new Proxy(s, {
		get(target, name) {
			const value = Reflect.get(target, name);
			if (name !== "get") return typeof value === "function" ? value.bind(target) : value;
			return (...args: Parameters<Store["get"]>) => {
				if (args[0].space.name === indexSpaceOf(indexed).name) aborted.abort();
				return target.get(...args);
			};
		},
	});
	expect(
		await eraseSubject(at(indexed, stopping), "alice", { signal: aborted.signal }),
	).toMatchObject({
		kind: "stopped",
		reason: "aborted",
	});
	expect(await records.create("b", "alice", 1, 60_000)).toBe("erased");
	expect(await records.read("a")).toBe(1);
	expect(await eraseSubject(at(indexed), "alice")).toMatchObject({ kind: "erased", removed: 1 });
	const down = new Proxy(s, {
		get(target, name) {
			const value = Reflect.get(target, name);
			if (name === "get") return () => Promise.reject(new Unavailable("test"));
			return typeof value === "function" ? value.bind(target) : value;
		},
	});
	expect(await eraseSubject(at(indexed, down), "bob")).toMatchObject({
		kind: "stopped",
		reason: "unavailable",
	});
});

it("sweeps from its subject's bucket a key whose record and set read absent, keeping one that lives", async () => {
	const { at, listed, indexOf } = await opened();
	const records = subjectRecordsIn<number>(at(indexed), "w", refuse);
	await listed(indexed, "alice", ["gone"]);
	await records.create("live", "alice", 1, 60_000);
	let swept = 0;
	let cursor: string | undefined;
	do {
		const page = await sweepIndex(at(indexed), cursor);
		swept += page.swept;
		cursor = page.cursor;
	} while (cursor !== undefined);
	expect(swept).toBe(1);
	expect(Object.values(await indexOf(indexed, "alice")).flat()).toEqual(["live"]);
});
