import { createHash } from "node:crypto";
import type { SubjectReading, Walk } from "@mod/erasure-extensions";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Json, type Key, type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import { expect, it } from "vitest";
import { indexSpaceOf, migrateRecords, subjectRecordsIn } from "../src/subject-records.ts";

const g = ["durable"] as const;
const indexed: Space = { name: "migrated-test", guarantees: g, subjectData: "online-indexed" };
const keyed: Space = { name: "migrated-keyed", guarantees: g, subjectData: "online-keyed" };
const bounded: Space = {
	name: "migrated-bounded",
	guarantees: g,
	subjectData: "bounded",
	boundedMs: 60_000,
};
const held = contract<Store>("test.store");
const refuse = (where: string, reason: string): never => {
	throw new Error(`${where}: ${reason}`);
};
const part = (space: Space, subject: string) =>
	`1.${createHash("sha256").update(`${space.name}\n${subject}`).digest("base64url")}`;
const bucketOf = (key: string) => `m${createHash("sha256").update(key).digest("hex")[0]}`;
const envelope = (subject: string, value: Json) => ({ "records:v": 1, subject, value });

/** An owner's reading where a record is keyed by its subject. */
const byKey: SubjectReading = async (key) => ({ kind: "subject", subject: key });

/** The owner's reading: the subject a value names, an orphan where it names `nobody`, unreadable where it says so. */
const owners: SubjectReading = async (_key, value) => {
	const named = (value as { owner?: string }).owner;
	if (named === "nobody") return { kind: "orphan" };
	if (named === "sealed") return { kind: "unreadable", reason: "sealed" };
	return named === undefined
		? { kind: "unreadable", reason: "no owner" }
		: { kind: "subject", subject: named };
};

async function opened() {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [
			simulated.module,
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
	const random = {
		bytes: (n: number) => new Uint8Array(n).map(() => Math.floor(Math.random() * 256)),
	};
	const at = (space: Space, phase: "reader" | "indexed" = "indexed") => ({
		store: s,
		space,
		index: indexSpaceOf(space),
		random,
		phase,
	});
	/** A walk of a space as the tool hands it in, every page on one server, each key `twice` where asked. */
	const walk = (twice = false): Walk => ({
		sweep: async (name, cursor) => {
			const space = [indexed, keyed, bounded].find((one) => one.name === name) as Space;
			const page = await s.scan(space, cursor);
			const keys: readonly Key[] = twice ? page.keys.flatMap((k) => [k, k]) : page.keys;
			return page.cursor === undefined
				? { keys, server: "one" }
				: { keys, cursor: page.cursor, server: "one" };
		},
	});
	const put = (space: Space, partition: string, value: Json, ms?: number) =>
		s.putIfAbsent({ space, partition, name: "record" }, value, {
			expiry: ms === undefined ? { kind: "never" } : { kind: "after", ms },
		});
	const raw = async (space: Space, partition: string) =>
		(await s.get({ space, partition, name: "record" })).entry;
	const index = async (space: Space, subject: string, name: string) =>
		(
			await s.get({
				space: indexSpaceOf(space),
				partition: `${part(space, subject)}.${name}`,
				name: "record",
			})
		).entry?.value;
	return { s, at, walk, put, raw, index };
}

it("indexes each raw record its owner reads as a subject's, keeping its value and end, and removes each proven an orphan", async () => {
	const { at, walk, put, raw, index } = await opened();
	await put(indexed, "a", { owner: "alice" }, 60_000);
	await put(indexed, "b", { owner: "bob" });
	await put(indexed, "o", { owner: "nobody" });
	expect(await migrateRecords(at(indexed), walk(), owners)).toEqual({
		kind: "migrated",
		space: indexed.name,
		indexed: 2,
		removed: 1,
	});
	expect((await raw(indexed, "a"))?.value).toEqual(envelope("alice", { owner: "alice" }));
	expect((await raw(indexed, "a"))?.expiresAt).toEqual(expect.any(Number));
	expect(await index(indexed, "alice", bucketOf("a"))).toEqual([["a", "record"]]);
	expect(await raw(indexed, "o")).toBeNull();
	// What the owner reads once indexed is its value as it was.
	const records = subjectRecordsIn<Json>(at(indexed), "w", refuse);
	expect(await records.read("b")).toEqual({ owner: "bob" });
	// Again: every record is migrated already, a key met twice in a walk too.
	expect(await migrateRecords(at(indexed), walk(true), owners)).toMatchObject({
		indexed: 0,
		removed: 0,
	});
	expect((await raw(indexed, "a"))?.value).toEqual(envelope("alice", { owner: "alice" }));
});

it("wraps a raw value of an envelope's shape whole, telling a migrated record by its witness, never by its shape", async () => {
	const { at, walk, put, raw, index } = await opened();
	// Raw, written before indexing: its shape is an envelope's, and nothing witnesses it.
	const lookalike = { ...envelope("carol", { n: 1 }), owner: "carol" };
	await put(keyed, "carol", envelope("carol", { owner: "carol" }));
	await put(keyed, "dave", lookalike);
	expect(await migrateRecords(at(keyed), walk(true), byKey)).toMatchObject({
		indexed: 2,
		removed: 0,
	});
	expect((await raw(keyed, "carol"))?.value).toEqual(
		envelope("carol", envelope("carol", { owner: "carol" })),
	);
	expect(await index(keyed, "carol", "witness.record")).toBe(1);
	const records = subjectRecordsIn<Json>(at(keyed), "w", refuse);
	expect(await records.read("carol")).toEqual(envelope("carol", { owner: "carol" }));
	expect(await records.read("dave")).toEqual(lookalike);
	// A rerun, as after a restore, wraps nothing twice; nor does a record the indexed builder wrote.
	expect(await records.create("erin", { owner: "erin" }, "endless", "erin")).toBe("created");
	expect(await migrateRecords(at(keyed), walk(), byKey)).toMatchObject({ indexed: 0, removed: 0 });
	expect(await records.read("erin")).toEqual({ owner: "erin" });
	// A record keyed by one subject that its owner reads as another's stops the space.
	await put(keyed, "fay", { owner: "gus" });
	expect(await migrateRecords(at(keyed), walk(), owners)).toMatchObject({
		kind: "stopped",
		reason: "a record keyed by another subject",
	});
});

it("stops a space at a record it cannot read, removing nothing more, and where records are not indexed", async () => {
	const { at, walk, put, raw } = await opened();
	await put(indexed, "s", { owner: "sealed" });
	await put(indexed, "o", { owner: "nobody" });
	const report = await migrateRecords(at(indexed), walk(), owners);
	expect(report).toMatchObject({ kind: "stopped", space: indexed.name });
	expect((report as { reason: string }).reason).toMatch(/^unreadable/);
	expect(await raw(indexed, "s")).not.toBeNull();
	expect(await migrateRecords(at(indexed, "reader"), walk(), owners)).toMatchObject({
		kind: "stopped",
		reason: "not-indexed",
	});
	// A bounded space has nothing to index: its records end by their end.
	expect(await migrateRecords(at(bounded), walk(), owners)).toEqual({
		kind: "migrated",
		space: bounded.name,
		indexed: 0,
		removed: 0,
	});
});

it("stops where aborted and finishes when run again; two runs at once index each record once", async () => {
	const { at, walk, put } = await opened();
	for (const key of ["a", "b", "c", "d"]) await put(indexed, key, { owner: "alice" });
	const aborted = AbortSignal.abort();
	expect(await migrateRecords(at(indexed), walk(), owners, { signal: aborted })).toMatchObject({
		kind: "stopped",
		reason: "aborted",
	});
	const [one, two] = await Promise.all([
		migrateRecords(at(indexed), walk(), owners),
		migrateRecords(at(indexed), walk(true), owners),
	]);
	expect([one, two].map((r) => (r as { indexed: number }).indexed).reduce((x, y) => x + y)).toBe(4);
	expect(await migrateRecords(at(indexed), walk(), owners)).toMatchObject({ indexed: 0 });
});
