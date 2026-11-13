/**
 * The one migration of records written before indexing, under the concurrency account erasure
 * admits (account erasure §5.1: once, in the maintenance window; every value then predates `indexed`):
 * no owner writes beside it (providers locked out, the epoch moved on), no erasure (enabled only
 * after it), and each run one tool process, so an operator running it twice is the
 * one race. Two runs at once, walks meeting a key twice or starting over, and runs that lose
 * replies, die, or see a failover or a restart all converge: every record its owner reads as a
 * subject's is kept whole in an envelope, listed once in that subject's bucket or witnessed, every
 * orphan is gone, and no record is counted by two runs. Erasure, enabled after, leaves no witness
 * or bucket entry beside a subject's data it removed, nor without data it kept; read from the
 * store itself, never through subject-records.
 *
 * The scheduling below is this file's own until store's `./testing` offers a plain hook (after G).
 * Per-PR runs are fixed: FC_SEED (default 20261111) and FC_RUNS (default 200).
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { createHash } from "node:crypto";
import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Json, type Key, type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import fc from "fast-check";
import { expect, it, vi } from "vitest";
import { eraseSubject, indexSpaceOf, migrateRecords } from "../../subject-records.ts";

const seed = Number(process.env.FC_SEED ?? 20261111);
const numRuns = Number(process.env.FC_RUNS ?? 200);

const g = ["no-eviction", "durable", "replicated"] as const;
const listed: Space = {
	name: "migrating-indexed",
	guarantees: [...g],
	subjectData: "online-indexed",
};
const keyed: Space = { name: "migrating-keyed", guarantees: [...g], subjectData: "online-keyed" };
const kinds = { listed, keyed } as const;
type Kind = keyof typeof kinds;
const subjects = ["alice", "bob", "carol"] as const;
type Subject = (typeof subjects)[number];
const opened = contract<Store>("test.migrating-store");

const part = (space: Space, subject: string) =>
	`1.${createHash("sha256").update(`${space.name}\n${subject}`).digest("base64url")}`;
const bucketName = (key: string) => `m${createHash("sha256").update(key).digest("hex")[0]}`;
const buckets = Array.from({ length: 16 }, (_, i) => `m${i.toString(16)}`);
const envelope = (subject: string, value: Json) => ({ "records:v": 1, subject, value });
/** Keys all in one bucket, so runs listing a subject's records contend for it. */
const listedKeys = Array.from({ length: 200 }, (_, i) => `k${i}`)
	.filter((k) => bucketName(k) === "m0")
	.slice(0, 6);

/** Bytes from a generated seed (xorshift32): the marks that settle resends, the same on every replay. */
const seededRandom = (from: number) => {
	let x = from | 0 || 1;
	return {
		bytes: (n: number) => {
			const out = new Uint8Array(n);
			for (let i = 0; i < n; i++) {
				x ^= x << 13;
				x ^= x >>> 17;
				x ^= x << 5;
				out[i] = x & 0xff;
			}
			return out;
		},
	};
};

/**
 * The owner's reading, as the contract asks: the subject a value names, an orphan only where it
 * names `nobody`, and unreadable for a value it never wrote, so nothing it cannot read is removed.
 */
const strict: SubjectReading = async (_key, value) => {
	const named = (value as { owner?: string }).owner;
	if (named === "nobody") return { kind: "orphan" };
	return named === undefined
		? { kind: "unreadable", reason: "names no owner" }
		: { kind: "subject", subject: named };
};
/**
 * A reading against the contract, calling a value it cannot read an orphan: the migration must not
 * rest on every owner's reading being right, so it must not remove a record another run migrated.
 */
const loose: SubjectReading = async (key, value) => {
	const read = await strict(key, value);
	return read.kind === "unreadable" ? { kind: "orphan" } : read;
};
const readings = { strict, loose } as const;

/** A raw record as written before indexing: its owner, and whether its shape is an envelope's. */
interface Raw {
	readonly owner: Subject | "nobody";
	readonly lookalike: boolean;
}
const rawValue = (key: string, r: Raw): Json =>
	r.lookalike ? { ...envelope(r.owner, { key }), owner: r.owner } : { owner: r.owner, key };

/** How a run's walk hands its keys in: pages of `page`, the keys at `again` met once more later, a new server at a page. */
interface WalkShape {
	readonly page: number;
	/** Where in the scanned keys the walk starts, going round: another server, another order. */
	readonly from: number;
	readonly again: readonly number[];
	readonly switchAt: number | undefined;
}
interface Run {
	readonly kind: Kind;
	readonly walk: WalkShape;
}
type Step =
	| {
			readonly kind: "runs";
			readonly runs: readonly Run[];
			readonly fault: "Lr" | "F" | "C" | undefined;
	  }
	// {fault:K}: one run dies before its `after`-th store call, sending nothing from then.
	| {
			readonly kind: "kill";
			readonly runs: readonly Run[];
			readonly victim: number;
			readonly after: number;
	  }
	// {fault:Lx}: every answer to the run's writes is lost, the writes applied or not.
	| { readonly kind: "lx"; readonly run: Run };

const walkShape: fc.Arbitrary<WalkShape> = fc.record({
	page: fc.integer({ min: 1, max: 4 }),
	from: fc.nat({ max: 5 }),
	again: fc.uniqueArray(fc.nat({ max: 5 }), { maxLength: 3 }),
	switchAt: fc.option(fc.integer({ min: 1, max: 3 }), { nil: undefined }),
});
const run: fc.Arbitrary<Run> = fc.record({
	kind: fc.constantFrom<Kind>("listed", "keyed"),
	walk: walkShape,
});
/** Runs at once lean to the same space: an operator running one command twice. */
const runsAtOnce = fc
	.tuple(
		fc.constantFrom<Kind>("listed", "keyed"),
		fc.array(walkShape, { minLength: 2, maxLength: 3 }),
	)
	.map(([kind, walks]) => walks.map((walk) => ({ kind, walk })));
const step: fc.Arbitrary<Step> = fc.oneof(
	{
		arbitrary: fc.record({
			kind: fc.constant("runs" as const),
			runs: fc.oneof<fc.Arbitrary<readonly Run[]>[]>(
				runsAtOnce,
				fc.array(run, { minLength: 1, maxLength: 3 }),
			),
			fault: fc.option(fc.constantFrom("Lr" as const, "F" as const, "C" as const), {
				nil: undefined,
			}),
		}),
		weight: 5,
	},
	{
		arbitrary: fc.record({
			kind: fc.constant("kill" as const),
			runs: runsAtOnce,
			victim: fc.nat({ max: 2 }),
			after: fc.nat({ max: 8 }),
		}),
		weight: 1,
	},
	{ arbitrary: fc.record({ kind: fc.constant("lx" as const), run }), weight: 1 },
);
const raws = fc.record({
	listed: fc.dictionary(
		fc.constantFrom(...(listedKeys as [string, ...string[]])),
		fc.record({
			owner: fc.constantFrom<Subject | "nobody">(...subjects, "nobody"),
			lookalike: fc.boolean(),
		}),
		{ minKeys: 1 },
	),
	keyed: fc.dictionary(
		fc.constantFrom(...subjects),
		fc.record({ orphan: fc.boolean(), lookalike: fc.boolean() }),
		{ minKeys: 1 },
	),
});

/** One simulated store holding both spaces and their indexes, each write a point the scheduler orders. */
async function migrating(s: fc.Scheduler | undefined, from: number) {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [
			simulated.module,
			defineModule({ name: "owner", replicaSafe: false, takes: [store] }, (m) => [
				...[listed, keyed].flatMap((space) => [
					m.contribute(spaces).by(() => space),
					m.contribute(spaces).by(() => indexSpaceOf(space)),
				]),
				m.provide(opened).by((c) => c.get(store)),
			]),
		],
		config: kernelConfig(),
		runtime: quietRuntime({ clock: { now: () => 1_800_000_000_000 } }),
	});
	const inner = app.get(opened);
	const command = new AsyncLocalStorage<number>();
	let live = false;
	const lostFor = new Set<number>();
	const killAt = new Map<number, number>();
	let died = () => {};
	/** Where an example acts at a point of its own: every call, by its run, hooks and space. */
	let atPoint = async (_label: string) => {};
	// Each hook arms the next before it waits, so every call of the operation in the space is a point.
	const arm = (hooks: "before" | "confirm", op: keyof Store, space: string) => {
		const at = hooks === "before" ? simulated.beforeNext : simulated.beforeConfirm;
		at(op, space, async () => {
			arm(hooks, op, space);
			const id = command.getStore();
			if (hooks === "before" && id !== undefined) {
				const left = killAt.get(id);
				if (left === 0) {
					died();
					return new Promise<void>(() => {});
				}
				if (left !== undefined) killAt.set(id, left - 1);
				if (lostFor.has(id) && op !== "get") simulated.loseNextReply();
			}
			await atPoint(`${id}:${hooks}:${op}:${space}`);
			if (live && s) await s.schedule(Promise.resolve(), `${id}:${hooks}:${op}:${space}`);
		});
	};
	for (const space of [listed, keyed].flatMap((one) => [one.name, indexSpaceOf(one).name])) {
		for (const op of ["get", "putIfAbsent", "replaceIf", "batch", "batchAcross"] as const) {
			arm("before", op, space);
			if (op !== "get") arm("confirm", op, space);
		}
	}
	const random = seededRandom(from);
	const placeOf = (kind: Kind) => ({
		store: inner,
		space: kinds[kind],
		index: indexSpaceOf(kinds[kind]),
		random,
		phase: "indexed" as const,
	});
	/** Every key of a space as its scan finds them, page after page. */
	const scanned = async (space: Space) => {
		const keys: Key[] = [];
		let cursor: string | undefined;
		do {
			const page = await inner.scan(space, cursor);
			keys.push(...page.keys);
			cursor = page.cursor;
		} while (cursor !== undefined);
		return keys;
	};
	/** A walk as the tool hands it in, shaped as `shape` says; each start scans the space afresh. */
	const walkOf = (shape: WalkShape): Walk => {
		let keys: Key[] = [];
		let server = "one";
		return {
			sweep: async (name, cursor) => {
				const space = [listed, keyed].find((one) => one.name === name) as Space;
				const at = cursor === undefined ? 0 : Number(cursor);
				if (at === 0) {
					const all = await scanned(space);
					const turn = all.length === 0 ? 0 : shape.from % all.length;
					const found = [...all.slice(turn), ...all.slice(0, turn)];
					keys = [...found, ...shape.again.flatMap((i) => (found[i] ? [found[i]] : []))];
				}
				if (shape.switchAt === at && server === "one") server = "two";
				const page = keys.slice(at * shape.page, (at + 1) * shape.page);
				const more = (at + 1) * shape.page < keys.length;
				return more ? { keys: page, cursor: String(at + 1), server } : { keys: page, server };
			},
		};
	};
	const raw = async (space: Space, partition: string) =>
		(await inner.get({ space, partition, name: "record" })).entry;
	// Runs until `run` settles: a scheduled store call where one waits, else the next of records'
	// resend pauses on the faked clock, else a turn for the calls under way.
	const scheduled = async <T>(go: () => Promise<T>) => {
		live = true;
		try {
			let settled = false;
			const running = go();
			running.then(
				() => {
					settled = true;
				},
				() => {
					settled = true;
				},
			);
			while (!settled) {
				if (s && s.count() > 0) await s.waitNext(1);
				else if (vi.getTimerCount() > 0) await vi.advanceTimersToNextTimerAsync();
				else await new Promise<void>((resolve) => setImmediate(resolve));
			}
			return await running;
		} finally {
			live = false;
		}
	};
	/** Settles when a run killed by `killAt` dies. */
	const dying = () =>
		new Promise<void>((resolve) => {
			died = resolve;
		});
	const at = (act: (label: string) => Promise<void>) => {
		atPoint = act;
	};
	return { simulated, inner, command, lostFor, killAt, dying, placeOf, walkOf, raw, scheduled, at };
}

const countsOf = (report: MigrationReport) =>
	(report as { kind: string; indexed?: number; removed?: number }).kind === "migrated"
		? (report as unknown as { indexed: number; removed: number })
		: undefined;

it("migrates every record written before indexing once, whole, into its subject's index, under two runs at once, repeated keys, restarts and lost, killed or failed-over runs; erasing then leaves no witness or entry beside the data", async () => {
	vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
	try {
		await fc.assert(
			fc.asyncProperty(
				fc.scheduler(),
				fc.integer(),
				raws,
				fc.array(step, { maxLength: 4 }),
				fc.subarray([...subjects]),
				fc.option(fc.constantFrom("Lr" as const, "F" as const, "C" as const), { nil: undefined }),
				fc.constantFrom<keyof typeof readings>("strict", "loose"),
				async (s, from, written, steps, erased, eraseFault, reading) => {
					const owners = readings[reading];
					const d = await migrating(s, from);
					// What was written before indexing, raw, as each owner wrote it.
					const before = {
						listed: Object.entries(written.listed).map(([key, r]) => ({ key, ...r })),
						keyed: Object.entries(written.keyed).map(([key, r]) => ({
							key,
							owner: (r.orphan ? "nobody" : key) as Subject | "nobody",
							lookalike: r.lookalike,
						})),
					};
					for (const kind of ["listed", "keyed"] as const) {
						for (const r of before[kind]) {
							await d.inner.putIfAbsent(
								{ space: kinds[kind], partition: r.key, name: "record" },
								rawValue(r.key, r),
								{ expiry: { kind: "never" } },
							);
						}
					}

					let ids = 0;
					const reports: { kind: Kind; report: MigrationReport | undefined }[] = [];
					const go = async (r: Run, set?: (id: number) => void) => {
						const id = ++ids;
						set?.(id);
						const report = await d.command.run(id, () =>
							migrateRecords(d.placeOf(r.kind), d.walkOf(r.walk), owners),
						);
						reports.push({ kind: r.kind, report });
					};
					const killed = () => reports.push({ kind: "listed", report: undefined });
					const fault = async (f: "Lr" | "F" | "C") => {
						if (f === "Lr") d.simulated.loseNextReply();
						if (f === "F") await d.simulated.failover();
						if (f === "C") await d.simulated.restart();
					};

					for (const st of steps) {
						if (st.kind === "runs") {
							const { fault: f } = st;
							// A fault lands among the runs, where the scheduler places it.
							const among = f
								? [s.schedule(Promise.resolve(), `fault:${f}`).then(() => fault(f))]
								: [];
							await d.scheduled(() => Promise.all([...st.runs.map((r) => go(r)), ...among]));
						} else if (st.kind === "kill") {
							const victim = st.victim % st.runs.length;
							const dead = d.dying();
							await d.scheduled(() =>
								Promise.all(
									st.runs.map((r, i) =>
										i === victim
											? Promise.race([go(r, (id) => d.killAt.set(id, st.after)), dead.then(killed)])
											: go(r),
									),
								),
							);
						} else {
							await d.scheduled(() => go(st.run, (id) => d.lostFor.add(id)));
						}
					}
					// A rerun with nothing failing finishes what any run left: the migration is done.
					for (const kind of ["listed", "keyed"] as const) {
						const last = await d.scheduled(() =>
							d.command.run(0, () =>
								migrateRecords(
									d.placeOf(kind),
									d.walkOf({ page: 2, from: 0, again: [], switchAt: undefined }),
									owners,
								),
							),
						);
						expect(last).toMatchObject({ kind: "migrated" });
						reports.push({ kind, report: last });
					}

					// Once: no record is counted by two runs, and where every run finished, each is counted.
					for (const kind of ["listed", "keyed"] as const) {
						const mine = reports.filter((r) => r.kind === kind);
						const counted = mine.map((r) => (r.report ? countsOf(r.report) : undefined));
						const indexed = counted.reduce((sum, c) => sum + (c?.indexed ?? 0), 0);
						const removed = counted.reduce((sum, c) => sum + (c?.removed ?? 0), 0);
						const subjectsOwned = before[kind].filter((r) => r.owner !== "nobody").length;
						const orphans = before[kind].length - subjectsOwned;
						expect(indexed, `${kind}: records indexed`).toBeLessThanOrEqual(subjectsOwned);
						expect(removed, `${kind}: orphans removed`).toBeLessThanOrEqual(orphans);
						if (
							counted.every((c) => c !== undefined) &&
							!reports.some((r) => r.report === undefined)
						) {
							expect(indexed, `${kind}: records indexed, every run finished`).toBe(subjectsOwned);
							expect(removed, `${kind}: orphans removed, every run finished`).toBe(orphans);
						}
					}

					/** What the index of `space` holds for `subject`, read from the store. */
					const listedFor = async (subject: string) => {
						const entries: unknown[] = [];
						for (const b of buckets) {
							const held = await d.raw(indexSpaceOf(listed), `${part(listed, subject)}.${b}`);
							if (held) entries.push(...(held.value as unknown[]).map((e) => [b, e]));
						}
						return entries.map((e) => JSON.stringify(e)).sort();
					};
					const witnessOf = async (subject: string) =>
						(await d.raw(indexSpaceOf(keyed), `${part(keyed, subject)}.witness.record`))?.value;

					// Whole and once: each subject's record its envelope, listed once or witnessed; each orphan gone.
					const converged = async (gone: ReadonlySet<string>) => {
						for (const r of before.listed) {
							const held = await d.raw(listed, r.key);
							if (r.owner === "nobody" || gone.has(r.owner)) expect(held, r.key).toBeNull();
							else expect(held?.value, r.key).toEqual(envelope(r.owner, rawValue(r.key, r)));
						}
						for (const subject of subjects) {
							const expected = gone.has(subject)
								? []
								: before.listed
										.filter((r) => r.owner === subject)
										.map((r) => JSON.stringify([bucketName(r.key), [r.key, "record"]]))
										.sort();
							expect(await listedFor(subject), `${subject}'s buckets`).toEqual(expected);
						}
						for (const r of before.keyed) {
							const held = await d.raw(keyed, r.key);
							const kept = r.owner !== "nobody" && !gone.has(r.owner);
							if (kept) expect(held?.value, r.key).toEqual(envelope(r.owner, rawValue(r.key, r)));
							else expect(held, r.key).toBeNull();
						}
						// A witness stands exactly where its subject's record does: never past it, never missing.
						for (const subject of subjects) {
							const record = await d.raw(keyed, subject);
							expect(await witnessOf(subject), `${subject}'s witness`).toBe(record ? 1 : undefined);
						}
					};
					await converged(new Set());

					// Erasure, enabled after the migration, erases subjects; a fault may land among them.
					const erasing = async () =>
						Promise.all(
							erased.flatMap((subject) =>
								(["listed", "keyed"] as const).map((kind) =>
									eraseSubject(d.placeOf(kind), subject),
								),
							),
						);
					const among = eraseFault
						? [s.schedule(Promise.resolve(), `fault:${eraseFault}`).then(() => fault(eraseFault))]
						: [];
					await d.scheduled(() => Promise.all([erasing(), ...among]));
					// Erasing again finishes what a fault stopped; then every erased subject's data is gone.
					const again = (await d.scheduled(erasing)) as SpaceReport[];
					for (const report of again) expect(report).toMatchObject({ kind: "erased" });
					await converged(new Set(erased));
					for (const subject of erased) {
						for (const space of [listed, keyed]) {
							expect(
								await d.raw(indexSpaceOf(space), `${part(space, subject)}.tomb`),
								`${subject}'s tombstone in ${space.name}`,
							).not.toBeNull();
						}
					}
				},
			),
			{ seed, numRuns },
		);
	} finally {
		vi.useRealTimers();
	}
}, 300_000);

// The counterexamples the property found in the migration (F1, F2), kept as examples whatever the seed.

/** One walk of a whole space, in its scan's order. */
const whole: WalkShape = { page: 6, from: 0, again: [], switchAt: undefined };

it("reports the migration done only on what is confirmed: after a run whose every reply was lost, a rerun then a failover leave no record raw", async () => {
	vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
	try {
		const d = await migrating(undefined, 1);
		const k = listedKeys[0] as string;
		const values = {
			listed: rawValue(k, { owner: "alice", lookalike: false }),
			keyed: rawValue("alice", { owner: "alice", lookalike: false }),
		};
		await d.inner.putIfAbsent({ space: listed, partition: k, name: "record" }, values.listed, {
			expiry: { kind: "never" },
		});
		await d.inner.putIfAbsent({ space: keyed, partition: "alice", name: "record" }, values.keyed, {
			expiry: { kind: "never" },
		});
		let id = 0;
		for (const kind of ["listed", "keyed"] as const) {
			// Every answer lost: its writes applied on the primary, none confirmed.
			id += 1;
			d.lostFor.add(id);
			const lost = await d.scheduled(() =>
				d.command.run(id, () => migrateRecords(d.placeOf(kind), d.walkOf(whole), strict)),
			);
			expect(lost).toMatchObject({ kind: "stopped", reason: "unavailable" });
		}
		for (const kind of ["listed", "keyed"] as const) {
			const rerun = await d.scheduled(() =>
				d.command.run(0, () => migrateRecords(d.placeOf(kind), d.walkOf(whole), strict)),
			);
			expect(rerun).toMatchObject({ kind: "migrated" });
		}
		// The migration is done; a failover keeps what it reported done.
		await d.simulated.failover();
		expect((await d.raw(listed, k))?.value).toEqual(envelope("alice", values.listed));
		expect(
			(await d.raw(indexSpaceOf(listed), `${part(listed, "alice")}.${bucketName(k)}`))?.value,
		).toEqual([[k, "record"]]);
		expect((await d.raw(keyed, "alice"))?.value).toEqual(envelope("alice", values.keyed));
		expect(
			(await d.raw(indexSpaceOf(keyed), `${part(keyed, "alice")}.witness.record`))?.value,
		).toBe(1);
	} finally {
		vi.useRealTimers();
	}
});

it("removes no record another run migrated meanwhile: a run reading as an orphan the envelope a failover took back removes nothing once the record is listed again", async () => {
	vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
	try {
		const d = await migrating(undefined, 1);
		const k = listedKeys[0] as string;
		const value = rawValue(k, { owner: "alice", lookalike: false });
		await d.inner.putIfAbsent({ space: listed, partition: k, name: "record" }, value, {
			expiry: { kind: "never" },
		});
		// Run 1 migrates k, every answer lost: the envelope stands on the primary only.
		d.lostFor.add(1);
		const lost = await d.scheduled(() =>
			d.command.run(1, () => migrateRecords(d.placeOf("listed"), d.walkOf(whole), strict)),
		);
		expect(lost).toMatchObject({ kind: "stopped", reason: "unavailable" });
		// Run 2 reads k as that envelope; a failover takes it back before run 2 reads the bucket,
		// and run 3 migrates k again while run 2's owner reads the envelope it holds.
		let failedOver = false;
		d.at(async (label) => {
			if (!failedOver && label === `2:before:get:${indexSpaceOf(listed).name}`) {
				failedOver = true;
				await d.simulated.failover();
			}
		});
		let again: MigrationReport | undefined;
		const reading: SubjectReading = async (key, read) => {
			// Once, from run 2's reading; run 3 reads through `loose` itself.
			if (again === undefined && d.command.getStore() === 2) {
				again = await d.command.run(3, () =>
					migrateRecords(d.placeOf("listed"), d.walkOf(whole), loose),
				);
			}
			return loose(key, read);
		};
		const second = await d.scheduled(() =>
			d.command.run(2, () => migrateRecords(d.placeOf("listed"), d.walkOf(whole), reading)),
		);
		expect(failedOver).toBe(true);
		expect(again).toMatchObject({ kind: "migrated", indexed: 1 });
		expect(second).not.toMatchObject({ removed: 1 });
		expect((await d.raw(listed, k))?.value).toEqual(envelope("alice", value));
		expect(
			(await d.raw(indexSpaceOf(listed), `${part(listed, "alice")}.${bucketName(k)}`))?.value,
		).toEqual([[k, "record"]]);
	} finally {
		vi.useRealTimers();
	}
});
