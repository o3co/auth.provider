import { createHash, randomBytes } from "node:crypto";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import { indexSpaceOf, subjectKeyedSetsIn, subjectRecordsIn } from "../src/subject-records.ts";

const g = ["durable"] as const;
const bounded: Space = {
	name: "fenced-test",
	guarantees: g,
	subjectData: "bounded",
	boundedMs: 60_000,
};
const indexed: Space = { name: "moved-test", guarantees: g, subjectData: "online-indexed" };
const keyed: Space = { name: "listed-test", guarantees: g, subjectData: "online-keyed" };
const held = contract<Store>("test.store");
const refuse = (where: string, reason: string): never => {
	throw new Error(`${where}: ${reason}`);
};
const clock = { now: () => Date.now() };

async function opened() {
	const app = await assemble({
		modules: [
			simulatedStore().module,
			defineModule({ name: "user", replicaSafe: false, takes: [store] }, (m) => [
				...[bounded, indexed, keyed].flatMap((space) => [
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
	const at = (space: Space, phase: "reader" | "indexed" = "indexed") => ({
		store: s,
		space,
		index: indexSpaceOf(space),
		random,
		phase,
	});
	const part = (space: Space, subject: string) =>
		`1.${createHash("sha256").update(`${space.name}\n${subject}`).digest("base64url")}`;
	const indexEntry = async (space: Space, subject: string, name: string) =>
		(
			await s.get({
				space: indexSpaceOf(space),
				partition: `${part(space, subject)}.${name}`,
				name: "record",
			})
		).entry?.value;
	return {
		s,
		at,
		indexEntry,
		raw: async (space: Space, partition: string, name = "record") =>
			(await s.get({ space, partition, name })).entry,
		erase: async (space: Space, subject: string) => {
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

it("creates a bounded record raw, within its space's ceiling, fenced by its subject's tombstone, its end kept on a change", async () => {
	const { at, raw, erase } = await opened();
	const records = subjectRecordsIn<number>(at(bounded), "w", refuse);
	await expect(records.create("k", "alice", 1, 60_001)).rejects.toThrow(TypeError);
	await expect(records.create("k", "alice", 1, "endless")).rejects.toThrow(TypeError);
	expect(await records.create("k", "alice", 1, 30_000)).toBe("created");
	const first = await raw(bounded, "k");
	expect(first?.value).toBe(1);
	expect(await records.change("k", (n) => ({ value: n + 1, lifetimeMs: 59_000 }))).toEqual({
		before: 1,
		after: 2,
	});
	expect((await raw(bounded, "k"))?.expiresAt).toBe(first?.expiresAt);
	await erase(bounded, "alice");
	expect(await records.create("other", "alice", 1, 30_000)).toBe("erased");
	await records.remove("k");
	expect(await raw(bounded, "k")).toBeNull();
});

it("keys a bounded space's records by secrets, kept under their names, and keys only a bounded space so", async () => {
	const { at, raw } = await opened();
	const records = subjectRecordsIn<string>(at(bounded), "w", refuse, { secret: true });
	expect(await records.create("s3cret", "alice", "held", 30_000)).toBe("created");
	expect(await records.read("s3cret")).toBe("held");
	const name = `1.${createHash("sha256").update(`${bounded.name}\ns3cret`).digest("base64url")}`;
	expect((await raw(bounded, name))?.value).toBe("held");
	expect(() => subjectRecordsIn(at(indexed), "w", refuse, { secret: true })).toThrow(/bounded/);
});

it("keeps a set in its subject's envelope, as keyed sets keep it, its key indexed, no member added past the tombstone", async () => {
	const { at, raw, indexEntry, erase } = await opened();
	const sets = subjectKeyedSetsIn({ ...at(indexed), cap: 5, clock }, "w", refuse);
	expect(await sets.add("grp", "alice", "one", 60_000)).toEqual({ pushedOut: [] });
	expect(await sets.add("grp", "alice", "two", 60_000)).toEqual({ pushedOut: [] });
	expect((await sets.members("grp")).map((m) => m.member)).toEqual(["one", "two"]);
	expect((await raw(indexed, "grp", "set"))?.value).toMatchObject({
		"records:v": 1,
		subject: "alice",
	});
	expect(await indexEntry(indexed, "alice", bucketOf("grp"))).toEqual(["grp"]);
	await sets.remove("grp", "one");
	expect((await sets.members("grp")).map((m) => m.member)).toEqual(["two"]);
	await erase(indexed, "alice");
	expect(await sets.add("grp", "alice", "three", 60_000)).toBe("erased");
	await sets.remove("grp", "two");
	expect(await sets.members("grp")).toEqual([]);
});

it("keeps a set keyed by its subject with no bucket, and a set written raw while records are only read", async () => {
	const { at, raw, indexEntry } = await opened();
	const sets = subjectKeyedSetsIn({ ...at(keyed), cap: 5, clock }, "w", refuse);
	await sets.add("alice", "alice", "s1", 60_000);
	expect(await indexEntry(keyed, "alice", bucketOf("alice"))).toBeUndefined();
	const reading = subjectKeyedSetsIn({ ...at(keyed, "reader"), cap: 5, clock }, "w", refuse);
	await reading.add("bob", "bob", "s2", 60_000);
	expect((await raw(keyed, "bob", "set"))?.value).toMatchObject({
		held: [["s2", expect.any(Number)]],
	});
});

it("moves a record from one subject to another as one, and answers missing, not-from and erased", async () => {
	const { at, raw, indexEntry, erase } = await opened();
	const records = subjectRecordsIn<number>(at(indexed), "w", refuse);
	await records.create("rec", "alice", 1, 60_000);
	expect(await records.move("rec", "bob", "carol")).toBe("not-from");
	expect(await records.move("none", "alice", "bob")).toBe("missing");
	expect(await records.move("rec", "alice", "bob")).toBe("moved");
	expect((await raw(indexed, "rec"))?.value).toEqual({ "records:v": 1, subject: "bob", value: 1 });
	expect(await indexEntry(indexed, "alice", bucketOf("rec"))).toBeUndefined();
	expect(await indexEntry(indexed, "bob", bucketOf("rec"))).toEqual(["rec"]);
	await erase(indexed, "carol");
	expect(await records.move("rec", "bob", "carol")).toBe("erased");
	expect((await raw(indexed, "rec"))?.value).toMatchObject({ subject: "bob" });
});
