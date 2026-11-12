/**
 * A migration's `migrated` means done: over any walk the tool hands in, pages split anyhow and the
 * server changing at any of them, `migrateRecords` and `migrateSets` answer `migrated` only where
 * no raw record or set of the space is left, the counts are what was raw, and erasing each subject
 * then leaves nothing of theirs, only tombstones; all read from the store itself. A walk whose
 * server changes at every page ends in `walk-unsteady`; a space holding an entry its owner cannot
 * read, or a malformed set, is `stopped`, never `migrated`. An `online-keyed` space has no sets to
 * index: they stay raw, and erasing each subject removes them.
 *
 * The walk is an input, not an interleaving: no scheduler. Per-PR runs are fixed: FC_SEED
 * (default 20261111) and FC_RUNS (default 200).
 */
import type { MigrationReport, SetReading, SubjectReading, Walk } from "@mod/erasure-extensions";
import type { Json, Key, Space } from "@mod/store";
import fc from "fast-check";
import { expect, it } from "vitest";
import { bucketOf, envelope, part, placed } from "../../../test/placed.ts";
import {
	eraseSubject,
	indexSpaceOf,
	migrateRecords,
	migrateSets,
	subjectRecordsIn,
} from "../../subject-records.ts";

const seed = Number(process.env.FC_SEED ?? 20261111);
const numRuns = Number(process.env.FC_RUNS ?? 200);

const g = ["durable"] as const;
const arms = {
	"records-indexed": { name: "done-records-indexed", guarantees: g, subjectData: "online-indexed" },
	"records-keyed": { name: "done-records-keyed", guarantees: g, subjectData: "online-keyed" },
	"sets-indexed": { name: "done-sets-indexed", guarantees: g, subjectData: "online-indexed" },
	"sets-keyed": { name: "done-sets-keyed", guarantees: g, subjectData: "online-keyed" },
} as const satisfies Record<string, Space>;
type Arm = keyof typeof arms;
const subjects = ["alice", "bob", "carol", "dave"] as const;
type Subject = (typeof subjects)[number];
const far = 9e15;
/** Calls of `sweep` past which a walk never ends: a migration that never stops it fails here. */
const endless = 400;

/**
 * One entry of a space before the run: its owner (`undefined`, an orphan), whether the owner
 * cannot read it, a set malformed, and a record already in its envelope, written once indexed.
 */
interface Entry {
	readonly key: string;
	readonly owner: Subject | undefined;
	readonly unreadable: boolean;
	readonly malformed: boolean;
	readonly enveloped: boolean;
}
/** How the walk hands the keys in: the order, page sizes in turn, and the calls whose server is new. */
interface WalkShape {
	readonly from: number;
	readonly sizes: readonly number[];
	readonly changes: "every" | readonly number[];
}
interface Case {
	readonly arm: Arm;
	readonly entries: readonly Entry[];
	readonly walk: WalkShape;
}

const rarely = fc.nat({ max: 11 }).map((n) => n === 0);
const owner = fc.option(fc.constantFrom(...subjects), { nil: undefined, freq: 4 });
const records = (keyed: boolean) =>
	(keyed
		? fc.uniqueArray(fc.constantFrom(...subjects), { minLength: 1, maxLength: 4 }).map((keys) =>
				keys.map((key) => ({
					key,
					owner: fc.option(fc.constant(key), { nil: undefined, freq: 3 }),
				})),
			)
		: fc
				.uniqueArray(fc.nat({ max: 11 }), { minLength: 1, maxLength: 8 })
				.map((ns) => ns.map((n) => ({ key: `k${n}`, owner })))
	).chain((made) =>
		fc.tuple(
			...made.map(({ key, owner: who }) =>
				fc.record({
					key: fc.constant(key),
					owner: who,
					unreadable: rarely,
					malformed: fc.constant(false),
					enveloped: rarely,
				}),
			),
		),
	);
/** Sets read by key alone: `login:<subject>` a subject's, `gone:<n>` an orphan. */
const sets = (keyed: boolean) =>
	(keyed
		? fc
				.uniqueArray(fc.constantFrom(...subjects), { minLength: 1, maxLength: 4 })
				.map((keys) => keys.map((key) => ({ key, owner: key as Subject | undefined })))
		: fc
				.uniqueArray(fc.option(fc.constantFrom(...subjects), { nil: undefined, freq: 3 }), {
					minLength: 1,
					maxLength: 5,
				})
				.chain((owners) =>
					fc.tuple(
						...owners.map((who) =>
							(who === undefined
								? fc.nat({ max: 3 }).map((n) => `gone:${n}`)
								: fc.constant(`login:${who}`)
							).map((key) => ({ key, owner: who })),
						),
					),
				)
				.map((made) => made.filter((one, at) => made.findIndex((o) => o.key === one.key) === at))
	).chain((made) =>
		fc.tuple(
			...made.map(({ key, owner: who }) =>
				fc.record({
					key: fc.constant(key),
					owner: fc.constant(who),
					unreadable: keyed ? fc.constant(false) : rarely,
					malformed: keyed ? fc.constant(false) : rarely,
					enveloped: fc.constant(false),
				}),
			),
		),
	);
const walkShape: fc.Arbitrary<WalkShape> = fc.record({
	from: fc.nat({ max: 7 }),
	sizes: fc.array(fc.integer({ min: 1, max: 4 }), { minLength: 1, maxLength: 4 }),
	changes: fc.oneof(
		{ arbitrary: fc.uniqueArray(fc.integer({ min: 1, max: 24 }), { maxLength: 8 }), weight: 4 },
		{ arbitrary: fc.constant("every" as const), weight: 1 },
	),
});
const cases: fc.Arbitrary<Case> = fc.oneof(
	...(["records-indexed", "records-keyed", "sets-indexed", "sets-keyed"] as const).map((arm) =>
		fc.record({
			arm: fc.constant(arm),
			entries: arm.startsWith("records")
				? records(arm.endsWith("keyed"))
				: sets(arm.endsWith("keyed")),
			walk: walkShape,
		}),
	),
);

/** A walk of the space's keys as first scanned, in the generated order, pages in turn, servers as said. */
function walking(s: Awaited<ReturnType<typeof placed>>["s"], space: Space, shape: WalkShape) {
	let asked = 0;
	let all: Key[] | undefined;
	const walk: Walk = {
		sweep: async (_name, cursor) => {
			if (all === undefined) {
				const found: Key[] = [];
				let on: string | undefined;
				do {
					const page = await s.scan(space, on);
					found.push(...page.keys);
					on = page.cursor;
				} while (on !== undefined);
				found.sort((a, b) => (String(a.partition) < String(b.partition) ? -1 : 1));
				const from = found.length === 0 ? 0 : shape.from % found.length;
				all = [...found.slice(from), ...found.slice(0, from)];
			}
			const call = asked++;
			if (call > endless) throw new Error("the walk never ends");
			const server =
				shape.changes === "every"
					? String(call)
					: String(shape.changes.filter((c) => c <= call).length);
			const at = cursor === undefined ? 0 : Number(cursor);
			const to = at + (shape.sizes[call % shape.sizes.length] ?? 1);
			const keys = all.slice(at, to);
			return to < all.length ? { keys, cursor: String(to), server } : { keys, server };
		},
	};
	return { walk, length: () => all?.length ?? 0 };
}

/** What a raw value is: a record naming its owner, or a set, well formed or not. */
const rawOf = (arm: Arm, e: Entry): Json =>
	arm.startsWith("records")
		? { owner: e.owner ?? "nobody" }
		: e.malformed
			? { held: [["a", far], ["b"]] }
			: [[`m-${e.key}`, far]];

/** The owner's readings: a record's subject from its value, a set's from its key; unreadable where generated. */
const recordReading =
	(entries: readonly Entry[]): SubjectReading =>
	async (key, value) => {
		if (entries.some((e) => e.key === key && e.unreadable))
			return { kind: "unreadable", reason: "sealed" };
		const named = (value as { owner?: string }).owner;
		return named === "nobody" || named === undefined
			? { kind: "orphan" }
			: { kind: "subject", subject: named };
	};
const setReading =
	(entries: readonly Entry[]): SetReading =>
	async (key) => {
		if (entries.some((e) => e.key === key && e.unreadable))
			return { kind: "unreadable", reason: "sealed" };
		const [form, subject] = key.split(":");
		return form === "login" && subject ? { kind: "subject", subject } : { kind: "orphan" };
	};

it("answers migrated only where nothing raw is left, the counts are what was raw, and erasing each subject leaves only tombstones", async () => {
	await fc.assert(
		fc.asyncProperty(cases, async ({ arm, entries, walk: shape }) => {
			const space = arms[arm];
			const name = arm.startsWith("records") ? "record" : "set";
			const keyed = arm.endsWith("keyed");
			const { s, simulated, at, put } = await placed([space]);
			const place = at(space, "indexed");
			const writer = subjectRecordsIn<Json>(place, "test", (where, reason) => {
				throw new Error(`${where}: ${reason}`);
			});
			for (const e of entries) {
				if (e.enveloped && e.owner !== undefined) {
					expect(await writer.create(e.key, rawOf(arm, e), "endless", e.owner)).toBe("created");
				} else await put(space, e.key, rawOf(arm, e), undefined, name);
			}
			const raw = entries.filter((e) => !(e.enveloped && e.owner !== undefined));
			const { walk, length } = walking(s, space, shape);
			const report: MigrationReport =
				name === "record"
					? await migrateRecords(place, walk, recordReading(entries))
					: await migrateSets(place, walk, setReading(entries));

			// Stopped, never migrated: a raw entry its owner cannot read, a malformed set, a walk changing at every page.
			const bad = raw.some((e) => e.unreadable || e.malformed);
			const firstPage = shape.sizes[0] ?? 1;
			const unsteady = shape.changes === "every" && length() > firstPage;
			if (arm !== "sets-keyed" && (bad || unsteady)) expect(report.kind).toBe("stopped");
			if (unsteady && !bad && arm !== "sets-keyed") {
				expect(report).toMatchObject({ reason: "walk-unsteady" });
			}
			if (shape.changes !== "every" && !bad) expect(report.kind).toBe("migrated");
			if (report.kind !== "migrated") return;

			// (c) The counts are what was raw: each raw entry a subject's indexed, each orphan removed.
			const owned = raw.filter((e) => e.owner !== undefined).length;
			expect(report).toEqual(
				arm === "sets-keyed"
					? { kind: "migrated", space: space.name, indexed: 0, removed: 0 }
					: { kind: "migrated", space: space.name, indexed: owned, removed: raw.length - owned },
			);

			// (a) Nothing raw is left: each entry an envelope of its owner, listed or witnessed; no orphan.
			const index = indexSpaceOf(space);
			const value = async (sp: Space, partition: string, n: string) =>
				(await s.get({ space: sp, partition, name: n })).entry?.value;
			for (const e of entries) {
				const held = await value(space, e.key, name);
				if (arm === "sets-keyed") {
					expect(held).toEqual(rawOf(arm, e));
					continue;
				}
				if (e.owner === undefined) {
					expect(held).toBeUndefined();
					continue;
				}
				expect(held).toEqual(envelope(e.owner, rawOf(arm, e)));
				if (keyed) {
					expect(e.owner).toBe(e.key);
					expect(await value(index, `${part(space, e.owner)}.witness.${name}`, "record")).toBe(1);
				} else {
					const listed = (await value(
						index,
						`${part(space, e.owner)}.${bucketOf(e.key)}`,
						"record",
					)) as readonly (readonly [string, string])[] | undefined;
					expect(listed?.filter(([k, n]) => k === e.key && n === name)).toHaveLength(1);
				}
			}

			// (b) Erasing each subject leaves nothing of theirs: the space empty, the index only tombstones.
			for (const subject of subjects) {
				expect(await eraseSubject(place, subject)).toMatchObject({ kind: "erased" });
			}
			// Past records' own `settled` marks (1 ms, holding `true`), which a standing clock keeps live.
			simulated.shiftClock(1_000);
			const left = async (sp: Space) => {
				const found: string[] = [];
				let on: string | undefined;
				do {
					const page = await s.scan(sp, on);
					found.push(...page.keys.map((k) => String(k.partition)));
					on = page.cursor;
				} while (on !== undefined);
				return found;
			};
			expect(await left(space)).toEqual([]);
			expect((await left(index)).filter((p) => !p.endsWith(".tomb"))).toEqual([]);
		}),
		{ seed, numRuns },
	);
});
