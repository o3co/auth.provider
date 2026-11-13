import { createHash } from "node:crypto";
import type { Space, Store } from "@mod/store";
import { expect, it } from "vitest";
import { indexSpaceOf, subjectKeyedSetsIn, subjectRecordsIn } from "../src/subject-records.ts";
import { bucketOf, part, placed } from "./placed.ts";

const g = ["durable"] as const;
const bounded: Space = {
	name: "fenced-test",
	guarantees: g,
	subjectData: "bounded",
	boundedMs: 60_000,
};
const indexed: Space = { name: "moved-test", guarantees: g, subjectData: "online-indexed" };
const keyed: Space = { name: "listed-test", guarantees: g, subjectData: "online-keyed" };
const refuse = (where: string, reason: string): never => {
	throw new Error(`${where}: ${reason}`);
};
const clock = { now: () => Date.now() };

async function opened() {
	const p = await placed([bounded, indexed, keyed]);
	return {
		s: p.s,
		at: (space: Space, phase: "reader" | "indexed" = "indexed") => p.at(space, phase),
		indexEntry: p.index,
		raw: p.raw,
		erase: async (space: Space, subject: string) => {
			const tomb = {
				space: indexSpaceOf(space),
				partition: `${part(space, subject)}.tomb`,
				name: "record",
			};
			await p.s.putIfAbsent(tomb, { at: 1 }, { expiry: { kind: "never" } });
		},
	};
}

it("creates a bounded record raw, within its space's ceiling, fenced by its subject's tombstone, its end kept on a change", async () => {
	const { at, raw, erase } = await opened();
	const records = subjectRecordsIn<number>(at(bounded), "w", refuse);
	await expect(records.create("k", 1, 60_001, "alice")).rejects.toThrow(TypeError);
	await expect(records.create("k", 1, "endless", "alice")).rejects.toThrow(TypeError);
	expect(await records.create("k", 1, 30_000, "alice")).toBe("created");
	const first = await raw(bounded, "k");
	expect(first?.value).toBe(1);
	expect(await records.change("k", (n) => ({ value: n + 1, lifetimeMs: 59_000 }))).toEqual({
		before: 1,
		after: 2,
	});
	expect((await raw(bounded, "k"))?.expiresAt).toBe(first?.expiresAt);
	await erase(bounded, "alice");
	expect(await records.create("other", 1, 30_000, "alice")).toBe("erased");
	await records.remove("k");
	expect(await raw(bounded, "k")).toBeNull();
});

it("keys a bounded space's records by secrets, kept under their names, and keys only a bounded space so", async () => {
	const { at, raw } = await opened();
	const records = subjectRecordsIn<string>(at(bounded), "w", refuse, { secret: true });
	expect(await records.create("s3cret", "held", 30_000, "alice")).toBe("created");
	expect(await records.read("s3cret")).toBe("held");
	const name = `1.${createHash("sha256").update(`${bounded.name}\ns3cret`).digest("base64url")}`;
	expect((await raw(bounded, name))?.value).toBe("held");
	expect(() => subjectRecordsIn(at(indexed), "w", refuse, { secret: true })).toThrow(/bounded/);
});

it("keeps a set in its subject's envelope, as keyed sets keep it, its key indexed, no member added past the tombstone", async () => {
	const { at, raw, indexEntry, erase } = await opened();
	const sets = subjectKeyedSetsIn({ ...at(indexed), cap: 5, clock }, "w", refuse);
	expect(await sets.add("grp", "one", 60_000, "alice")).toEqual({ pushedOut: [] });
	expect(await sets.add("grp", "two", 60_000, "alice")).toEqual({ pushedOut: [] });
	expect((await sets.members("grp")).map((m) => m.member)).toEqual(["one", "two"]);
	expect((await raw(indexed, "grp", "set"))?.value).toMatchObject({
		"records:v": 1,
		subject: "alice",
	});
	expect(await indexEntry(indexed, "alice", bucketOf("grp"))).toEqual([["grp", "set"]]);
	await sets.remove("grp", "one");
	expect((await sets.members("grp")).map((m) => m.member)).toEqual(["two"]);
	await erase(indexed, "alice");
	expect(await sets.add("grp", "three", 60_000, "alice")).toBe("erased");
	await sets.remove("grp", "two");
	expect(await sets.members("grp")).toEqual([]);
});

it("keeps a set keyed by its subject with no bucket, and a set written raw while records are only read", async () => {
	const { at, raw, indexEntry } = await opened();
	const sets = subjectKeyedSetsIn({ ...at(keyed), cap: 5, clock }, "w", refuse);
	await sets.add("alice", "s1", 60_000, "alice");
	expect(await indexEntry(keyed, "alice", bucketOf("alice"))).toBeUndefined();
	expect(await indexEntry(keyed, "alice", "witness.set")).toBe(1);
	const reading = subjectKeyedSetsIn({ ...at(keyed, "reader"), cap: 5, clock }, "w", refuse);
	await reading.add("bob", "s2", 60_000, "bob");
	expect((await raw(keyed, "bob", "set"))?.value).toMatchObject({
		held: [["s2", expect.any(Number)]],
	});
});

it("writes every category in reader over a store without a batch across, and refuses that store once indexed", async () => {
	const { s, at } = await opened();
	const { batchAcross: _, ...lacking } = s;
	const lone = (space: Space, phase: "reader" | "indexed" = "reader") => ({
		...at(space, phase),
		store: lacking as Store,
	});
	for (const space of [indexed, keyed, bounded]) {
		const records = subjectRecordsIn<number>(lone(space), "w", refuse);
		expect(await records.create("alice", 1, 30_000, "alice")).toBe("created");
		expect(await records.change("alice", (n) => ({ value: n + 1 }))).toEqual({
			before: 1,
			after: 2,
		});
		expect(await records.read("alice")).toBe(2);
		await records.remove("alice");
		expect(await records.read("alice")).toBeUndefined();
	}
	const sets = subjectKeyedSetsIn({ ...lone(keyed), cap: 5, clock }, "w", refuse);
	expect(await sets.add("alice", "m", 60_000, "alice")).toEqual({ pushedOut: [] });
	expect((await sets.members("alice")).map((m) => m.member)).toEqual(["m"]);
	expect(() => subjectRecordsIn(lone(indexed, "indexed"), "w", refuse)).toThrow(
		"w: its store writes no records of two partitions as one",
	);
	expect(() =>
		subjectKeyedSetsIn({ ...lone(keyed, "indexed"), cap: 5, clock }, "w", refuse),
	).toThrow("w: its store writes no records of two partitions as one");
});
