import { createHash, randomBytes } from "node:crypto";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Json, type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import { kept, opened, ownersValue } from "../src/envelope/envelope.ts";
import { indexSpaceOf, type Phase, subjectRecordsIn } from "../src/subject-records.ts";

const indexedSpace: Space = {
	name: "subjects-test",
	guarantees: ["durable"],
	subjectData: "online-indexed",
};
const keyedSpace: Space = {
	name: "keyed-test",
	guarantees: ["durable"],
	subjectData: "online-keyed",
};
const held = contract<Store>("test.store");

/** A store of both spaces and their indexes, and what a space and a subject's part of its index hold, raw. */
async function opened_() {
	const app = await assemble({
		modules: [
			simulatedStore().module,
			defineModule({ name: "user", replicaSafe: false, takes: [store] }, (m) => [
				...[indexedSpace, keyedSpace].flatMap((space) => [
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
	const random = { bytes: (n: number) => new Uint8Array(randomBytes(n)) };
	const refuse = (where: string, reason: string): never => {
		throw new Error(`${where}: ${reason}`);
	};
	const part = (space: Space, subject: string) =>
		`1.${createHash("sha256").update(`${space.name}\n${subject}`).digest("base64url")}`;
	return {
		s,
		random,
		build: <T extends Json>(phase: Phase, space = indexedSpace) =>
			subjectRecordsIn<T>(
				{ store: s, space, index: indexSpaceOf(space), random, phase },
				"test.records",
				refuse,
			),
		raw: async (key: string, space = indexedSpace) =>
			(await s.get({ space, partition: key, name: "record" })).entry?.value,
		/** Every entry of the subject's part of the index, by its name after the subject's part. */
		indexOf: async (subject: string, space = indexedSpace) => {
			const prefix = `${part(space, subject)}.`;
			const found: Record<string, Json> = {};
			let cursor: string | undefined;
			do {
				const page = await s.scan(indexSpaceOf(space), cursor);
				for (const k of page.keys.filter(
					(k) => k.partition.startsWith(prefix) && k.name === "record",
				)) {
					found[k.partition.slice(prefix.length)] = (await s.get(k)).entry?.value as Json;
				}
				cursor = page.cursor;
			} while (cursor !== undefined);
			return found;
		},
		erase: async (subject: string, space = indexedSpace) => {
			const tomb = {
				space: indexSpaceOf(space),
				partition: `${part(space, subject)}.tomb`,
				name: "record",
			};
			await s.putIfAbsent(tomb, { at: 1 }, { expiry: { kind: "never" } });
		},
	};
}

const bucketOf = (key: string) => `m${createHash("sha256").update(key).digest("hex")[0]}`;
const envelope = (subject: string, value: Json) => ({ "records:v": 1, subject, value });

it("opens an envelope by its exact shape alone, and refuses an owner's value holding its mark at the top", () => {
	expect(opened(envelope("alice", { a: 1 }))).toEqual({ value: { a: 1 }, subject: "alice" });
	for (const raw of [
		{ "records:v": 1, subject: "alice", value: 1, more: true },
		{ "records:v": 2, subject: "alice", value: 1 },
		{ "records:v": 1, subject: 7, value: 1 },
		{ "records:v": 1, subject: "alice" },
		[1],
		"text",
		null,
	] as Json[]) {
		expect(opened(raw)).toEqual({ value: raw });
	}
	expect(kept(1, undefined)).toBe(1);
	expect(() => ownersValue({ "records:v": 1 })).toThrow(TypeError);
	expect(ownersValue({ inner: { "records:v": 1 } })).toEqual({ inner: { "records:v": 1 } });
});

it("writes raw, and no index, while records are only read as they were", async () => {
	const { build, raw, indexOf } = await opened_();
	const records = build<number>("reader");
	expect(await records.create("k", "alice", 1, 60_000)).toBe("created");
	expect(await raw("k")).toBe(1);
	expect(await indexOf("alice")).toEqual({});
});

it("keeps a record in its subject's envelope and its key in the subject's bucket, no subject in a key", async () => {
	const { build, raw, indexOf } = await opened_();
	const records = build<{ n: number }>("indexed");
	expect(await records.create("a", "alice", { n: 1 }, 60_000)).toBe("created");
	expect(await records.create("a", "alice", { n: 2 }, 60_000)).toBe("exists");
	expect(await raw("a")).toEqual(envelope("alice", { n: 1 }));
	expect(await records.read("a")).toEqual({ n: 1 });
	expect(await indexOf("alice")).toEqual({ [bucketOf("a")]: ["a"] });
	expect((await records.scan()).keys).toEqual(["a"]);
});

it("puts every key a subject's racing creates make into its index", async () => {
	const { build, indexOf } = await opened_();
	const records = build<number>("indexed");
	const keys = Array.from({ length: 12 }, (_, i) => `k${i}`);
	expect(await Promise.all(keys.map((k) => records.create(k, "alice", 1, 60_000)))).toEqual(
		keys.map(() => "created"),
	);
	const listed = Object.values(await indexOf("alice")).flat() as string[];
	expect([...listed].sort()).toEqual([...keys].sort());
});

it("writes nothing past a subject's tombstone: a create answers erased, a change nothing, while a removal goes", async () => {
	const { build, raw, indexOf, erase } = await opened_();
	const records = build<number>("indexed");
	await records.create("kept", "alice", 1, 60_000);
	await erase("alice");
	expect(await records.create("new", "alice", 1, 60_000)).toBe("erased");
	expect(await raw("new")).toBeUndefined();
	expect(await records.change("kept", (n) => ({ value: n + 1 }))).toBeUndefined();
	expect(await raw("kept")).toEqual(envelope("alice", 1));
	await records.remove("kept");
	expect(await raw("kept")).toBeUndefined();
	expect(Object.keys(await indexOf("alice"))).toEqual(["tomb"]);
	expect(await records.create("other", "bob", 1, 60_000)).toBe("created");
});

it("changes a record in its envelope from its attempt, leaving the index as it was", async () => {
	const { build, raw, indexOf } = await opened_();
	const records = build<number>("indexed");
	await records.create("a", "alice", 1, 60_000);
	const before = await indexOf("alice");
	let deadline = 0;
	const changed = await records.change("a", (n, attempt) => {
		deadline = attempt.deadline;
		return { value: n + 1 };
	});
	expect(changed).toEqual({ before: 1, after: 2 });
	expect(deadline).toBeGreaterThan(0);
	expect(await raw("a")).toEqual(envelope("alice", 2));
	expect(await indexOf("alice")).toEqual(before);
});

it("removes a key from its bucket with its record, and the bucket with its last key", async () => {
	const { build, indexOf } = await opened_();
	const records = build<number>("indexed");
	await records.create("a", "alice", 1, 60_000);
	await records.create("b", "alice", 1, 60_000);
	await records.remove("a");
	expect(Object.values(await indexOf("alice")).flat()).toEqual(["b"]);
	await records.remove("b");
	expect(await indexOf("alice")).toEqual({});
});

it("changes a record kept raw, from before records were indexed, raw", async () => {
	const { s, build, raw } = await opened_();
	await s.putIfAbsent({ space: indexedSpace, partition: "old", name: "record" }, 1, {
		expiry: { kind: "never" },
	});
	const records = build<number>("indexed");
	expect(await records.change("old", (n) => ({ value: n + 1 }))).toEqual({ before: 1, after: 2 });
	expect(await raw("old")).toBe(2);
});

it("keeps only the tombstone for records keyed by their subject: no bucket, and nothing past it", async () => {
	const { build, indexOf, erase } = await opened_();
	const records = build<number>("indexed", keyedSpace);
	expect(await records.create("s-alice", "alice", 1, "endless")).toBe("created");
	expect(await indexOf("alice", keyedSpace)).toEqual({});
	await erase("alice", keyedSpace);
	expect(await records.create("s-alice-2", "alice", 1, "endless")).toBe("erased");
});

it("refuses to build without a batch across, over an index not the space's, or a space of another category", async () => {
	const { s, random } = await opened_();
	const refuse = (where: string, reason: string): never => {
		throw new Error(`${where}: ${reason}`);
	};
	const { batchAcross: _, ...without } = s;
	const at =
		(space: Space, index = indexSpaceOf(space), store_ = s) =>
		() =>
			subjectRecordsIn({ store: store_, space, index, random, phase: "indexed" }, "w", refuse);
	expect(at(indexedSpace, indexSpaceOf(indexedSpace), without as Store)).toThrow(/two partitions/);
	expect(at(indexedSpace, { ...indexSpaceOf(indexedSpace), name: "other.index" })).toThrow(/index/);
	expect(at(indexedSpace, { ...indexSpaceOf(indexedSpace), guarantees: [] })).toThrow(/index/);
	expect(at({ ...indexedSpace, subjectData: "none" })).toThrow(/category/);
	expect(at({ name: indexedSpace.name, guarantees: indexedSpace.guarantees })).toThrow(/category/);
});
