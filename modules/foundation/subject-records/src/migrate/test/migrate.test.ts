import type { Elsewhere, SubjectReading } from "@mod/erasure-extensions";
import type { Json, Space } from "@mod/store";
import { expect, it } from "vitest";
import { bucketOf, envelope, placed } from "../../../test/placed.ts";
import { migrateRecords, subjectRecordsIn } from "../../subject-records.ts";

const g = ["durable"] as const;
const indexed: Space = { name: "migrated-test", guarantees: g, subjectData: "online-indexed" };
const keyed: Space = { name: "migrated-keyed", guarantees: g, subjectData: "online-keyed" };
const bounded: Space = {
	name: "migrated-bounded",
	guarantees: g,
	subjectData: "bounded",
	boundedMs: 60_000,
};
const refuse = (where: string, reason: string): never => {
	throw new Error(`${where}: ${reason}`);
};

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

const opened = () => placed([indexed, keyed, bounded]);

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

it("decides a record already migrated in one confirmed change, never on reads alone, which a failover could take back", async () => {
	const { s, at, walk, put } = await opened();
	await put(indexed, "k", { owner: "alice" });
	expect(await migrateRecords(at(indexed), walk(), owners)).toMatchObject({ indexed: 1 });
	// A rerun reads k migrated: it confirms that with a write of its own, as records does.
	const sent: string[] = [];
	const counting = new Proxy(s, {
		get: (target, name) => {
			const got = Reflect.get(target, name);
			if ((name !== "batch" && name !== "batchAcross") || typeof got !== "function") return got;
			return (...args: unknown[]) => {
				sent.push(String(name));
				return got.apply(target, args);
			};
		},
	});
	expect(await migrateRecords({ ...at(indexed), store: counting }, walk(), owners)).toMatchObject({
		indexed: 0,
		removed: 0,
	});
	expect(sent.length).toBeGreaterThan(0);
});

it("removes as an orphan no record another run migrated meanwhile: the removal holds its envelope's listing", async () => {
	const { s, at, walk, put, raw, index } = await opened();
	const value = { owner: "alice" };
	// An envelope no bucket lists, as a failover leaves a migration it took back half seen.
	await put(indexed, "k0", envelope("alice", value));
	let raced = false;
	// An owner whose reading takes what it cannot tell for an orphan; while it reads, another run
	// migrates k0 again, from the raw value the failover left, to the very same envelope.
	const loose: SubjectReading = async (key, held) => {
		if (!raced && (held as { "records:v"?: number })["records:v"] === 1) {
			raced = true;
			await s.replaceIf(
				{ space: indexed, partition: key, name: "record" },
				(await raw(indexed, key))?.version ?? "",
				value,
				{ expiry: { kind: "keep" } },
			);
			await migrateRecords(at(indexed), walk(), owners);
			return { kind: "orphan" };
		}
		return owners(key, held);
	};
	const report = await migrateRecords(at(indexed), walk(), loose);
	expect(raced).toBe(true);
	expect(report).toMatchObject({ kind: "migrated", removed: 0 });
	expect((await raw(indexed, "k0"))?.value).toEqual(envelope("alice", value));
	expect(await index(indexed, "alice", bucketOf("k0"))).toEqual([["k0", "record"]]);
});

it("runs the owner's step for each orphan before removing it, on the value it confirmed, counting it removed; none for a subject's record", async () => {
	const { at, walk, put, raw } = await opened();
	await put(indexed, "a", { owner: "alice" });
	await put(indexed, "o", { owner: "nobody", issuer: "x" });
	const kept: [string, unknown, boolean][] = [];
	const elsewhere: Elsewhere = async (key, value) => {
		// The source is still there while the step runs: the removal comes after it.
		kept.push([key, value, (await raw(indexed, key)) !== null]);
	};
	expect(await migrateRecords(at(indexed), walk(), owners, { elsewhere })).toEqual({
		kind: "migrated",
		space: indexed.name,
		indexed: 1,
		removed: 1,
	});
	expect(kept).toEqual([["o", { owner: "nobody", issuer: "x" }, true]]);
	expect(await raw(indexed, "o")).toBeNull();
});

it("stops the space where the owner's step throws, keeping that orphan and removing nothing more", async () => {
	const { at, walk, put, raw } = await opened();
	await put(indexed, "o", { owner: "nobody" });
	const elsewhere: Elsewhere = async () => {
		throw new TypeError("no room");
	};
	expect(await migrateRecords(at(indexed), walk(), owners, { elsewhere })).toEqual({
		kind: "stopped",
		space: indexed.name,
		reason: "elsewhere: TypeError",
	});
	expect((await raw(indexed, "o"))?.value).toEqual({ owner: "nobody" });
});

it("runs the owner's step again on a record changed before its removal, removing the value it kept last", async () => {
	const { s, at, walk, put, raw } = await opened();
	await put(indexed, "o", { owner: "nobody", issuer: "old" });
	let changedOnce = false;
	const kept: unknown[] = [];
	const elsewhere: Elsewhere = async (_key, value) => {
		kept.push(value);
		if (changedOnce) return;
		changedOnce = true;
		// Another writer changes the record after the step read it, before the removal.
		const key = { space: indexed, partition: "o", name: "record" };
		const { entry } = await s.get(key);
		await s.replaceIf(
			key,
			entry?.version ?? "",
			{ owner: "nobody", issuer: "new" },
			{
				expiry: { kind: "never" },
			},
		);
	};
	expect(await migrateRecords(at(indexed), walk(), owners, { elsewhere })).toMatchObject({
		kind: "migrated",
		removed: 1,
	});
	expect(kept).toEqual([
		{ owner: "nobody", issuer: "old" },
		{ owner: "nobody", issuer: "new" },
	]);
	expect(await raw(indexed, "o")).toBeNull();
});

it("stops a space holding a record saved as unowned where the owner reads it unreadable, removing nothing; with its step, keeps it elsewhere and removes it", async () => {
	const { at, walk, raw } = await opened();
	const writer = subjectRecordsIn<Json>(at(indexed, "reader"), "w", refuse);
	expect(await writer.unowned("names", { issuer: "x" }, "endless")).toBe("created");
	const unread: SubjectReading = async () => ({ kind: "unreadable", reason: "a name" });
	expect(await migrateRecords(at(indexed), walk(), unread)).toMatchObject({
		kind: "stopped",
		reason: "unreadable: a name",
	});
	expect((await raw(indexed, "names"))?.value).toEqual({ issuer: "x" });
	const kept = new Map<string, unknown>();
	const orphan: SubjectReading = async () => ({ kind: "orphan" });
	expect(
		await migrateRecords(at(indexed), walk(), orphan, {
			elsewhere: async (key, value) => {
				kept.set(key, value);
			},
		}),
	).toMatchObject({ kind: "migrated", removed: 1 });
	expect([...kept]).toEqual([["names", { issuer: "x" }]]);
	expect(await raw(indexed, "names")).toBeNull();
});
