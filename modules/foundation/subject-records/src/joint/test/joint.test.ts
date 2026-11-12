import { isUnavailable } from "@mod/kernel";
import type { Json, Space, Store } from "@mod/store";
import { expect, it } from "vitest";
import { bucketOf, envelope, part, placed } from "../../../test/placed.ts";
import { eraseSubject, indexSpaceOf } from "../../subject-records.ts";
import { type JointOp, jointRecordsIn } from "../joint.ts";

const g = ["durable"] as const;
const lists: Space = { name: "joint-lists", guarantees: g, subjectData: "online-indexed" };
const claims: Space = { name: "joint-claims", guarantees: g, subjectData: "online-indexed" };
const refuse = (where: string, reason: string): never => {
	throw new Error(`${where}: ${reason}`);
};
const create = (value: Json, subject: string): JointOp => ({
	kind: "create",
	value,
	lifetimeMs: "endless",
	subject,
});
const change = (value: Json): JointOp => ({ kind: "change", value });
const move = (value: Json, to: string): JointOp => ({ kind: "move", value, to });
const remove: JointOp = { kind: "remove" };

async function opened(phase: "reader" | "indexed" = "indexed", over?: (s: Store) => Store) {
	const p = await placed([lists, claims]);
	const store = over ? over(p.s) : p.s;
	const places = {
		lists: { ...p.at(lists, phase), store },
		claims: { ...p.at(claims, phase), store },
	};
	const { changeSubjectRecords } = jointRecordsIn(places, "joint-test", refuse);
	/** An entry of a subject's bucket for `key`, as `index` lists it. */
	const listed = async (space: Space, subject: string, key: string) =>
		((await p.index(space, subject, bucketOf(key))) as Json[] | undefined)?.some(
			(e) => JSON.stringify(e) === JSON.stringify([key, "record"]),
		) ?? false;
	const erase = (space: Space, subject: string) => eraseSubject(p.at(space), subject);
	/** The subject's tombstone alone, its records left: as they stand while they await their eraser. */
	const tombed = (space: Space, subject: string) =>
		p.s.putIfAbsent(
			{ space: indexSpaceOf(space), partition: `${part(space, subject)}.tomb`, name: "record" },
			{ at: 1 },
			{ expiry: { kind: "never" } },
		);
	/** What the store holds under the key, raw: an envelope where it wrote one. */
	const held = async (space: Space, key: string) => (await p.raw(space, key))?.value;
	return { ...p, places, changeSubjectRecords, listed, erase, tombed, held };
}

it("creates records of two places as one, each in its envelope and its subject's bucket, and answers each before and after", async () => {
	const { changeSubjectRecords, held, listed } = await opened();
	const answer = await changeSubjectRecords({
		targets: [
			{ place: "lists", key: "alice" },
			{ place: "claims", key: "c1" },
		],
		decide: () => ({ targets: [create({ f: 1 }, "alice"), create({ l: "alice" }, "alice")] }),
	});
	expect(answer).toEqual({
		kind: "written",
		targets: [
			{ before: undefined, after: { value: { f: 1 }, subject: "alice" } },
			{ before: undefined, after: { value: { l: "alice" }, subject: "alice" } },
		],
		watched: [],
	});
	expect(await held(lists, "alice")).toEqual(envelope("alice", { f: 1 }));
	expect([await listed(lists, "alice", "alice"), await listed(claims, "alice", "c1")]).toEqual([
		true,
		true,
	]);
	// Two records in one bucket: the ops compose on it, each listed.
	const [k1, k2] = Array.from({ length: 64 }, (_, i) => `same-${i}`).filter(
		(key, _, all) => bucketOf(key) === bucketOf(all[0] as string),
	);
	await changeSubjectRecords({
		targets: [
			{ place: "claims", key: k1 as string },
			{ place: "claims", key: k2 as string },
		],
		decide: () => ({ targets: [create({}, "alice"), create({}, "alice")] }),
	});
	expect([
		await listed(claims, "alice", k1 as string),
		await listed(claims, "alice", k2 as string),
	]).toEqual([true, true]);
	// No op for any record: written, nothing changed.
	const none = await changeSubjectRecords({
		targets: [{ place: "lists", key: "alice" }],
		decide: () => ({}),
	});
	expect(none).toMatchObject({ kind: "written", targets: [{ after: { value: { f: 1 } } }] });
});

it("moves a claim from one subject to another with both lists, both tombstones held in the one write", async () => {
	const { changeSubjectRecords, held, listed } = await opened();
	const seed = await changeSubjectRecords({
		targets: [
			{ place: "lists", key: "alice" },
			{ place: "claims", key: "c1" },
		],
		decide: () => ({ targets: [create(["c1"], "alice"), create({ l: "alice" }, "alice")] }),
	});
	expect(seed.kind).toBe("written");
	// bob takes c1 over: the claim moved, bob's list made, alice's list watched and changed.
	const takeover = () =>
		changeSubjectRecords({
			targets: [
				{ place: "claims", key: "c1" },
				{ place: "lists", key: "bob" },
			],
			watch: ([claim]) => [
				{ place: "lists", key: (claim?.value as { l: string } | undefined)?.l ?? "" },
			],
			decide: () => ({
				targets: [move({ l: "bob" }, "bob"), create(["c1"], "bob")],
				watched: [change([])],
			}),
		});
	expect(await takeover()).toMatchObject({
		kind: "written",
		targets: [
			{ before: { subject: "alice" }, after: { value: { l: "bob" }, subject: "bob" } },
			{ before: undefined, after: { subject: "bob" } },
		],
		watched: [{ before: { value: ["c1"] }, after: { value: [] } }],
	});
	expect(await held(claims, "c1")).toEqual(envelope("bob", { l: "bob" }));
	expect([await listed(claims, "alice", "c1"), await listed(claims, "bob", "c1")]).toEqual([
		false,
		true,
	]);
});

it("holds every subject's tombstone a change names in its one write: one landing before it makes the change read again", async () => {
	let raced: (() => Promise<unknown>) | undefined;
	const racing = (store: Store) =>
		new Proxy(store, {
			get(target, name) {
				if (name === "batchAcross") {
					return async (...args: Parameters<NonNullable<Store["batchAcross"]>>) => {
						const run = raced;
						raced = undefined;
						await run?.();
						return target.batchAcross?.(...args);
					};
				}
				const value = Reflect.get(target, name);
				return typeof value === "function" ? value.bind(target) : value;
			},
		});
	const { changeSubjectRecords, held, erase } = await opened("indexed", racing);
	await changeSubjectRecords({
		targets: [{ place: "claims", key: "c1" }],
		decide: () => ({ targets: [create({ l: "alice" }, "alice")] }),
	});
	// dave's tombstone lands between the move's read and its write: the write fails, and the reread refuses.
	raced = () => erase(claims, "dave");
	expect(
		await changeSubjectRecords({
			targets: [{ place: "claims", key: "c1" }],
			decide: () => ({ targets: [move({ l: "dave" }, "dave")] }),
		}),
	).toEqual({ kind: "refused", at: { in: "targets", index: 0 }, why: "erased" });
	expect(raced).toBeUndefined();
	expect(await held(claims, "c1")).toEqual(envelope("alice", { l: "alice" }));
});

it("moves by the subject a record is read under: to an erased subject refused, from an erased one unavailable, to its own a change, raw a raw change", async () => {
	const { changeSubjectRecords, held, erase, tombed, put } = await opened();
	const make = (key: string, subject: string) =>
		changeSubjectRecords({
			targets: [{ place: "claims", key }],
			decide: () => ({ targets: [create({ n: 0 }, subject)] }),
		});
	const moved = (key: string, to: string) =>
		changeSubjectRecords({
			targets: [{ place: "claims", key }],
			decide: () => ({ targets: [move({ n: 1 }, to)] }),
		});
	await make("k1", "alice");
	await make("k2", "bob");
	expect(await moved("none", "alice")).toEqual({
		kind: "refused",
		at: { in: "targets", index: 0 },
		why: "missing",
	});
	await erase(claims, "erin");
	expect(await moved("k1", "erin")).toEqual({
		kind: "refused",
		at: { in: "targets", index: 0 },
		why: "erased",
	});
	expect(await held(claims, "k1")).toEqual(envelope("alice", { n: 0 }));
	await tombed(claims, "bob");
	// bob's records await their eraser: a move from him is unavailable, nothing written.
	await make("k3", "frank");
	const fromErased = changeSubjectRecords({
		targets: [{ place: "claims", key: "k2" }],
		decide: () => ({ targets: [move({ n: 1 }, "frank")] }),
	});
	await expect(fromErased).rejects.toSatisfy(isUnavailable);
	expect(await moved("k1", "alice")).toMatchObject({
		kind: "written",
		targets: [{ after: { value: { n: 1 }, subject: "alice" } }],
	});
	await put(claims, "k4", { n: 0 });
	expect(await moved("k4", "alice")).toMatchObject({
		kind: "written",
		targets: [{ after: { value: { n: 1 } } }],
	});
	expect(await held(claims, "k4")).toEqual({ n: 1 });
});

it("refuses a change at the first record its rule refuses, writing nothing, and answers a removal of nothing as written", async () => {
	const { changeSubjectRecords, held, erase, tombed } = await opened();
	const tried = (ops: readonly JointOp[], keys: readonly string[]) =>
		changeSubjectRecords({
			targets: keys.map((key) => ({ place: "lists" as const, key })),
			decide: () => ({ targets: ops }),
		});
	await tried([create({ n: 0 }, "alice"), create({ n: 0 }, "gus")], ["alice", "gus"]);
	expect(
		await tried([create({ n: 1 }, "bob"), create({ n: 9 }, "alice")], ["bob", "alice"]),
	).toEqual({
		kind: "refused",
		at: { in: "targets", index: 1 },
		why: "exists",
	});
	expect(await held(lists, "bob")).toBeUndefined();
	expect(await tried([change({ n: 1 })], ["nobody"])).toMatchObject({ why: "missing" });
	await tombed(lists, "gus");
	await erase(lists, "hal");
	// gus' record awaits its eraser: a change of it is `erased`, and so is a create for hal.
	expect(await tried([change({ n: 1 })], ["gus"])).toMatchObject({
		kind: "refused",
		why: "erased",
	});
	expect(await tried([create({ n: 1 }, "hal")], ["hal"])).toMatchObject({ why: "erased" });
	expect(await held(lists, "hal")).toBeUndefined();
	expect(await tried([remove], ["nobody"])).toEqual({
		kind: "written",
		targets: [{ before: undefined, after: undefined }],
		watched: [],
	});
});

it("clears the records a holder names through ops on watched records, each answered before and after", async () => {
	const { changeSubjectRecords, held, listed } = await opened();
	await changeSubjectRecords({
		targets: [
			{ place: "lists", key: "alice" },
			{ place: "claims", key: "a" },
			{ place: "claims", key: "b" },
		],
		decide: () => ({
			targets: [create(["a", "b"], "alice"), create({}, "alice"), create({}, "alice")],
		}),
	});
	const cleared = await changeSubjectRecords({
		targets: [{ place: "lists", key: "alice" }],
		watch: ([list]) =>
			((list?.value as string[] | undefined) ?? []).map((key) => ({ place: "claims", key })),
		decide: (_read, watched) => ({ targets: [change([])], watched: watched.map(() => remove) }),
	});
	expect(cleared).toMatchObject({
		kind: "written",
		watched: [
			{ before: { subject: "alice" }, after: undefined },
			{ before: { subject: "alice" }, after: undefined },
		],
	});
	expect([await held(claims, "a"), await held(claims, "b")]).toEqual([undefined, undefined]);
	expect([await listed(claims, "alice", "a"), await listed(claims, "alice", "b")]).toEqual([
		false,
		false,
	]);
});

it("decides again on what a racing writer left, and writes raw where records are only read", async () => {
	const { changeSubjectRecords, simulated, s } = await opened();
	await changeSubjectRecords({
		targets: [{ place: "lists", key: "alice" }],
		decide: () => ({ targets: [create({ n: 0 }, "alice")] }),
	});
	let decided = 0;
	let raced = false;
	simulated.beforeNext("batchAcross", "joint-lists", async () => {
		if (raced) return;
		raced = true;
		const at = { space: lists, partition: "alice", name: "record" };
		const { entry } = await s.get(at);
		await s.replaceIf(at, entry?.version ?? "", envelope("alice", { n: 5 }), {
			expiry: { kind: "keep" },
		});
	});
	const answer = await changeSubjectRecords({
		targets: [{ place: "lists", key: "alice" }],
		decide: ([list]) => {
			decided += 1;
			return { targets: [change({ n: ((list?.value as { n: number } | undefined)?.n ?? 0) + 1 })] };
		},
	});
	expect(answer).toMatchObject({ targets: [{ after: { value: { n: 6 } } }] });
	expect(decided).toBeGreaterThan(1);
	const reader = await opened("reader");
	expect(
		await reader.changeSubjectRecords({
			targets: [{ place: "lists", key: "r" }],
			decide: () => ({ targets: [create({ n: 0 }, "rita")] }),
		}),
	).toMatchObject({ kind: "written", targets: [{ after: { value: { n: 0 } } }] });
	expect(await reader.held(lists, "r")).toEqual({ n: 0 });
});

it("refuses at build a place of another category, a store writing no two partitions as one, and differing guarantees", async () => {
	const p = await placed([lists, claims]);
	const keyed: Space = { name: "joint-keyed", guarantees: g, subjectData: "online-keyed" };
	const k = await placed([keyed]);
	expect(() => jointRecordsIn({ k: k.at(keyed) }, "w", refuse)).toThrow(/online-indexed|category/);
	const noAcross = new Proxy(p.s, {
		get: (target, name) => (name === "batchAcross" ? undefined : Reflect.get(target, name, target)),
	});
	for (const phase of ["reader", "indexed"] as const) {
		expect(() =>
			jointRecordsIn({ l: { ...p.at(lists, phase), store: noAcross } }, "w", refuse),
		).toThrow(/two partitions/);
	}
	const other: Space = {
		name: "joint-other",
		guarantees: ["durable", "replicated"],
		subjectData: "online-indexed",
	};
	const o = await placed([other]);
	expect(() =>
		jointRecordsIn({ l: p.at(lists), o: { ...o.at(other), store: p.s } }, "w", refuse),
	).toThrow(/guarantees/);
	expect(() => jointRecordsIn({ l: p.at(lists), o: o.at(other) }, "w", refuse)).toThrow(
		/one store/,
	);
});
