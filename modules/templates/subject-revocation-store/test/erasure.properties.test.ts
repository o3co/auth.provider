import { AsyncLocalStorage } from "node:async_hooks";
import { erasureMarks } from "@mod/erasure-extensions";
import { assemble, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Key, type Store, store, storeControl } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import {
	type BoundaryKind,
	erasureFence,
	erasureGuards,
	revocations,
	subjectErasure,
} from "@mod/subject-revocation";
import revocationModule from "@mod/subject-revocation/module";
import fc from "fast-check";
import { expect, it, vi } from "vitest";
import wiring from "../src/module.ts";

const boundariesSpace = "subject-revocation-store.boundaries";
const receiptsSpace = "subject-revocation-store.receipts";
const hostNow = 1_800_000_000_000;
const subjects = ["alice", "bob"] as const;
const receiptIds = ["r1", "r2", "r3"] as const;

/** Bytes from a generated seed (xorshift32): the runtime's randomness, the same on every replay. */
const seededRandom = (seed: number) => {
	let x = seed | 0 || 1;
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

/** A store call as an instance made it: the command it was made for, and what it answered. */
interface Call {
	readonly by: number | undefined;
	readonly op: string;
	readonly args: readonly unknown[];
	answer?: {
		readonly kind?: string;
		readonly version?: string;
		readonly versions?: readonly (string | null)[];
	};
}

const operations = [
	"get",
	"putIfAbsent",
	"replaceIf",
	"removeIf",
	"take",
	"batch",
	"batchAcross",
	"count",
	"getMany",
	"now",
	"scan",
] as const;

/** The store as is, each call noted with the command it was made for: it changes nothing. */
function noted(inner: Store, calls: Call[], command: AsyncLocalStorage<number>): Store {
	const entries = operations.flatMap((op) => {
		const f = (
			inner as unknown as Record<string, ((...a: unknown[]) => Promise<never>) | undefined>
		)[op];
		if (typeof f !== "function") return [];
		const wrapped = async (...args: unknown[]) => {
			const call: Call = { by: command.getStore(), op, args };
			calls.push(call);
			const answer = await f.apply(inner, args);
			call.answer = answer;
			return answer;
		};
		return [[op, wrapped] as const];
	});
	return Object.fromEntries(entries) as unknown as Store;
}

/**
 * A write the store committed, with the version it minted. Commit order from `simulatedStore`'s one
 * version counter; the Store contract gives versions no order, so `countedUp` checks it each step.
 */
interface Commit {
	readonly version: number;
	readonly by: number | undefined;
	readonly key: Key;
	readonly value: unknown;
	readonly conditions: readonly { readonly key: Key }[];
}

function commitsOf(calls: readonly Call[]): Commit[] {
	return calls.flatMap((call): Commit[] => {
		const { op, args, answer, by } = call;
		if ((op === "putIfAbsent" || op === "replaceIf") && answer?.kind === "written") {
			const value = op === "putIfAbsent" ? args[1] : args[2];
			return [{ version: Number(answer.version), by, key: args[0] as Key, value, conditions: [] }];
		}
		if (op === "batchAcross" && answer?.kind === "committed") {
			const [conditions, writes] = args as [{ key: Key }[], { key: Key; put?: unknown }[]];
			return (answer.versions ?? []).flatMap((v, i) =>
				v === null
					? []
					: [
							{
								version: Number(v),
								by,
								key: (writes[i] as { key: Key }).key,
								value: writes[i]?.put,
								conditions,
							},
						],
			);
		}
		return [];
	});
}

const sameKey = (key: Key, space: string, partition: string) =>
	key.space.name === space && key.partition === partition && key.name === "record";

/**
 * Whether the versions still count up, as the commit order read from them needs: each is an integer,
 * minted for one key only (one count across keys), and a boundary (never expired, never removed)
 * holds a version no lower than any committed to it.
 */
function countedUp(commits: readonly Commit[], held: ReadonlyMap<string, string | undefined>) {
	const keyOf = (key: Key) => `${key.space.name}/${key.partition}/${key.name}`;
	const minted = new Map<number, string>();
	for (const c of commits) {
		expect(Number.isInteger(c.version), "a version that is no count").toBe(true);
		// One count for every key: a version minted again for another key is no order across keys.
		const first = minted.get(c.version) ?? keyOf(c.key);
		expect(keyOf(c.key), `version ${c.version} minted for ${first} and again`).toBe(first);
		minted.set(c.version, first);
	}
	for (const [partition, version] of held) {
		const committed = commits
			.filter((c) => sameKey(c.key, boundariesSpace, partition))
			.map((c) => c.version);
		if (committed.length === 0) continue;
		expect(
			Number(version),
			`${partition}'s boundary holds a version below one committed to it`,
		).toBeGreaterThanOrEqual(Math.max(...committed));
	}
}

type Instance = 0 | 1;
type Act =
	| {
			readonly kind: "fence";
			readonly at: Instance;
			readonly subject: string;
			readonly receipt: string;
	  }
	| { readonly kind: "mark"; readonly at: Instance; readonly subject: string }
	| {
			readonly kind: "revoke";
			readonly at: Instance;
			readonly subject: string;
			readonly keep: boolean;
	  }
	| {
			readonly kind: "compare";
			readonly at: Instance;
			readonly subject: string;
			readonly offsetMs: number;
			readonly boundary: BoundaryKind;
			readonly allowanceMs: number;
	  };
type Step =
	| Act
	| { readonly kind: "together"; readonly acts: readonly Act[] }
	// {fault:K}: one of them dies before its `after`-th store call, sending nothing from then.
	| {
			readonly kind: "kill";
			readonly acts: readonly Act[];
			readonly victim: number;
			readonly after: number;
	  }
	// {fault:Lx}: every answer to its writes is lost, the writes applied or not.
	| { readonly kind: "lx"; readonly act: Act }
	| { readonly kind: "fault"; readonly fault: "Lr" | "F" | "C" }
	| { readonly kind: "clock"; readonly ms: number };

const instance = fc.constantFrom<Instance>(0, 1);
const subject = fc.constantFrom(...subjects);
const writing: fc.Arbitrary<Act> = fc.oneof(
	fc.record({
		kind: fc.constant("fence" as const),
		at: instance,
		subject,
		receipt: fc.constantFrom(...receiptIds),
	}),
	fc.record({ kind: fc.constant("mark" as const), at: instance, subject }),
	fc.record({ kind: fc.constant("revoke" as const), at: instance, subject, keep: fc.boolean() }),
);
const act: fc.Arbitrary<Act> = fc.oneof(
	{ arbitrary: writing, weight: 4 },
	{
		arbitrary: fc.record({
			kind: fc.constant("compare" as const),
			at: instance,
			subject,
			offsetMs: fc.integer({ min: -20_000, max: 200_000 }),
			boundary: fc.constantFrom<BoundaryKind>("sessions", "delegations"),
			allowanceMs: fc.integer({ min: -1000, max: 60_000 }),
		}),
		weight: 1,
	},
);
const step: fc.Arbitrary<Step> = fc.oneof(
	{ arbitrary: act, weight: 6 },
	{
		arbitrary: fc.record({
			kind: fc.constant("together" as const),
			acts: fc.array(writing, { minLength: 2, maxLength: 3 }),
		}),
		weight: 3,
	},
	{
		arbitrary: fc.record({
			kind: fc.constant("kill" as const),
			acts: fc.array(writing, { minLength: 2, maxLength: 3 }),
			victim: fc.nat({ max: 2 }),
			after: fc.nat({ max: 4 }),
		}),
		weight: 1,
	},
	{ arbitrary: fc.record({ kind: fc.constant("lx" as const), act: writing }), weight: 1 },
	{
		arbitrary: fc.record({
			kind: fc.constant("fault" as const),
			fault: fc.constantFrom("Lr" as const, "F" as const, "C" as const),
		}),
		weight: 1,
	},
	{
		arbitrary: fc.record({
			kind: fc.constant("clock" as const),
			ms: fc.integer({ min: 1, max: 70_000 }),
		}),
		weight: 1,
	},
);

/** Two instances over one simulated store, erasure enabled, each store call a point the scheduler orders. */
async function deployment(s: fc.Scheduler, seed: number) {
	const simulated = simulatedStore();
	simulated.mark(erasureMarks.enabled, true);
	const command = new AsyncLocalStorage<number>();
	const calls: Call[] = [];
	let live = false;
	/** Commands whose every write answer is lost ({fault:Lx}), and those killed after so many calls ({fault:K}). */
	const lostFor = new Set<number>();
	const killAt = new Map<number, number>();
	let died = () => {};
	// Each hook arms the next before it waits, so every call of the operation in the space is a point.
	const arm = (hooks: "before" | "confirm", op: keyof Store, space: string) => {
		const at = hooks === "before" ? simulated.beforeNext : simulated.beforeConfirm;
		at(op, space, async () => {
			arm(hooks, op, space);
			const id = command.getStore();
			if (hooks === "before" && id !== undefined) {
				const left = killAt.get(id);
				if (left === 0) {
					// Killed: this call is never sent, nor anything after it.
					died();
					return new Promise<void>(() => {});
				}
				if (left !== undefined) killAt.set(id, left - 1);
				if (lostFor.has(id) && op !== "get") simulated.loseNextReply();
			}
			if (live) await s.schedule(Promise.resolve(), `${id}:${hooks}:${op}:${space}`);
		});
	};
	for (const space of [boundariesSpace, receiptsSpace]) {
		for (const op of ["get", "putIfAbsent", "replaceIf", "batchAcross"] as const) {
			arm("before", op, space);
			if (op !== "get") arm("confirm", op, space);
		}
	}
	const runtime = quietRuntime({ clock: { now: () => hostNow }, random: seededRandom(seed) });
	const base = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime,
	});
	const guard = defineModule({ name: "guard", replicaSafe: true, takes: [] }, (m) => [
		m.contribute(erasureGuards).by(() => ({ name: "guard" })),
	]);
	const shared = defineModule({ name: "store", replicaSafe: true, takes: [] }, (m) => [
		m.provide(store).by(() => noted(base.get(store), calls, command)),
		m.provide(storeControl).by(() => base.get(storeControl)),
	]);
	const instances = await Promise.all(
		[0, 1].map(async () => {
			const app = await assemble({
				modules: [shared, wiring, revocationModule, guard],
				config: kernelConfig(),
				runtime,
			});
			return {
				fence: app.get(erasureFence),
				erasure: app.get(subjectErasure),
				revocations: app.get(revocations),
			};
		}),
	);
	const raw = (space: string, partition: string) =>
		base.get(store).get({ space: { name: space, guarantees: [] }, partition, name: "record" });
	// Runs until `run` settles: a scheduled store call where one waits, else the next of records'
	// resend pauses on the faked clock, else a turn for the calls under way.
	const scheduled = async <T>(run: () => Promise<T>) => {
		live = true;
		try {
			let settled = false;
			const running = run();
			running.then(
				() => {
					settled = true;
				},
				() => {
					settled = true;
				},
			);
			while (!settled) {
				if (s.count() > 0) await s.waitNext(1);
				else if (vi.getTimerCount() > 0) await vi.advanceTimersToNextTimerAsync();
				else await new Promise<void>((resolve) => setImmediate(resolve));
			}
			return await running;
		} finally {
			live = false;
		}
	};
	/** Settles when a command killed by `killAt` dies. */
	const dying = () =>
		new Promise<void>((resolve) => {
			died = resolve;
		});
	return { simulated, command, calls, instances, raw, scheduled, lostFor, killAt, dying };
}

/** What the model knows of a fence call once it answered. */
interface Fenced {
	readonly id: number;
	readonly subject: string;
	readonly receipt: string;
	readonly invokedAt: number;
	readonly answer: "passed" | "erased" | "used";
}

const runs = Number(process.env.FC_RUNS ?? 200);
const seed = Number(process.env.FC_SEED ?? 20261111);

it("passes a fence only on a receipt it wrote, held by its subject's boundary and committed before that subject's mark of erasure, which no write drops, across two instances, resends, failovers and restarts", async () => {
	// Records' resend pauses run on a faked clock: a reply lost every time costs no wall time.
	vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
	try {
		await fc.assert(
			fc.asyncProperty(
				fc.scheduler(),
				fc.integer(),
				fc.array(step, { maxLength: 14 }),
				async (s, randomSeed, steps) => {
					const d = await deployment(s, randomSeed);
					let clock = 0;
					let ids = 0;
					const marks = new Map<string, { readonly first: number; readonly resolvedAt: number }>();
					const fenced: Fenced[] = [];
					const unseen: Commit[] = [];

					const exec = async (a: Act, set?: (id: number) => void) => {
						const id = ++ids;
						set?.(id);
						const invokedAt = ++clock;
						const at = d.instances[a.at] as (typeof d.instances)[number];
						const once = () =>
							d.command.run(id, async () => {
								switch (a.kind) {
									case "fence":
										return at.fence.fence(a.subject, a.receipt);
									case "mark":
										return at.erasure.markErased(a.subject);
									case "revoke":
										return at.revocations.record(a.subject, { keepDelegations: a.keep });
									case "compare":
										return at.revocations.compare(
											a.subject,
											hostNow + a.offsetMs,
											a.boundary,
											a.allowanceMs,
										);
								}
							});
						// {fault:Lr}: a call left unavailable is sent once again, as a client would.
						// A fence whose receipt id is used throws, never passes: noted as `used`, checked below.
						const settled = async () => {
							try {
								return await once();
							} catch (error) {
								if (a.kind === "fence" && !isUnavailable(error)) return "used";
								throw error;
							}
						};
						let answer: unknown;
						try {
							answer = await settled();
						} catch (error) {
							if (!isUnavailable(error)) throw error;
							try {
								answer = await settled();
							} catch (again) {
								if (!isUnavailable(again)) throw again;
								return;
							}
						}
						const resolvedAt = ++clock;
						if (a.kind === "mark") {
							const { erasedAt } = answer as { erasedAt: number };
							const held = marks.get(a.subject);
							// The first mark is kept: every later answer is it.
							if (held) expect(erasedAt).toBe(held.first);
							else marks.set(a.subject, { first: erasedAt, resolvedAt });
						}
						if (a.kind === "fence") {
							fenced.push({
								id,
								subject: a.subject,
								receipt: a.receipt,
								invokedAt,
								answer: answer as Fenced["answer"],
							});
						}
						if (a.kind === "compare" && marks.has(a.subject)) expect(answer).toBe("revoked");
					};

					for (const st of steps) {
						switch (st.kind) {
							case "together":
								await d.scheduled(() => Promise.all(st.acts.map((a) => exec(a))));
								break;
							case "kill": {
								const victim = st.victim % st.acts.length;
								const dead = d.dying();
								await d.scheduled(() =>
									Promise.all(
										st.acts.map((a, i) =>
											i === victim
												? Promise.race([exec(a, (id) => d.killAt.set(id, st.after)), dead])
												: exec(a),
										),
									),
								);
								break;
							}
							case "lx":
								await d.scheduled(() => exec(st.act, (id) => d.lostFor.add(id)));
								break;
							case "fault":
								if (st.fault === "Lr") d.simulated.loseNextReply();
								if (st.fault === "F") await d.simulated.failover();
								if (st.fault === "C") await d.simulated.restart();
								break;
							case "clock":
								d.simulated.shiftClock(st.ms);
								break;
							default:
								await d.scheduled(() => exec(st));
						}

						// A write whose every answer was lost is seen only in the store: where a boundary holds a
						// mark no seen write set, the write that set it is the last to that boundary (an {fault:Lx}
						// step runs alone). A failover or restart may drop it again: then so does this.
						for (const s of subjects) {
							const { entry } = await d.raw(boundariesSpace, s);
							const markHeld =
								(entry?.value as { erasedAt?: unknown } | undefined)?.erasedAt !== undefined;
							const at = unseen.findIndex((c) => sameKey(c.key, boundariesSpace, s));
							if (
								at >= 0 &&
								(!markHeld || Number(entry?.version) < (unseen[at] as Commit).version)
							) {
								unseen.splice(at, 1);
							}
							const seen = [...commitsOf(d.calls), ...unseen].some(
								(c) =>
									sameKey(c.key, boundariesSpace, s) &&
									(c.value as { erasedAt?: unknown } | undefined)?.erasedAt !== undefined,
							);
							if (entry && markHeld && !seen) {
								unseen.push({
									version: Number(entry.version),
									by: undefined,
									key: {
										space: { name: boundariesSpace, guarantees: [] },
										partition: s,
										name: "record",
									},
									value: entry.value,
									conditions: [],
								});
							}
						}

						// The mark is never dropped: the stored boundary opens with the first mark.
						for (const [subjectMarked, { first }] of marks) {
							const { entry } = await d.raw(boundariesSpace, subjectMarked);
							expect((entry?.value as { erasedAt?: unknown } | undefined)?.erasedAt).toBe(first);
						}
						const held = new Map<string, string | undefined>();
						for (const s of subjects) held.set(s, (await d.raw(boundariesSpace, s)).entry?.version);
						countedUp([...commitsOf(d.calls), ...unseen], held);

						// A fence that passed did so on a receipt it wrote itself, held by its own subject's
						// boundary, committed before any write that set that subject's mark. The receipt it passed
						// on is the last one under its id as of the fence's own commit (a receipt, or the settled
						// mark kept under the same conditions). A fence thrown as `used` met a receipt under its id.
						const commits = [...commitsOf(d.calls), ...unseen];
						const heldBy = (c: Commit, s: string) =>
							c.conditions.some((cond) => sameKey(cond.key, boundariesSpace, s));
						for (const f of fenced) {
							if (f.answer === "used") {
								// Any other call that sent a receipt under the id: its answer may have been lost.
								const earlier = d.calls.some(
									(c) =>
										c.by !== f.id &&
										c.op === "batchAcross" &&
										(c.args[1] as { key: Key }[]).some((w) =>
											sameKey(w.key, receiptsSpace, f.receipt),
										),
								);
								expect(earlier, `fence ${f.id} thrown with no receipt under ${f.receipt}`).toBe(
									true,
								);
							}
							if (f.answer !== "passed") continue;
							const own = commits
								.filter(
									(c) =>
										c.by === f.id &&
										c.key.space.name === receiptsSpace &&
										c.key.partition === f.receipt,
								)
								.filter((c) => heldBy(c, f.subject))
								.at(-1);
							expect(
								own,
								`fence ${f.id} (${f.subject}, ${f.receipt}) committed nothing`,
							).toBeDefined();
							if (!own) continue;
							const passedOn = commits
								.filter((c) => sameKey(c.key, receiptsSpace, f.receipt) && c.version <= own.version)
								.sort((a, b) => a.version - b.version)
								.at(-1);
							expect(passedOn, `fence ${f.id} passed on no receipt`).toBeDefined();
							expect(
								passedOn?.by === f.id && heldBy(passedOn, f.subject),
								`fence ${f.id} (${f.subject}, ${f.receipt}) passed on a receipt it did not write (written by call ${passedOn?.by}, held by ${
									passedOn?.conditions.find((cond) => cond.key.space.name === boundariesSpace)?.key
										.partition
								}'s boundary)`,
							).toBe(true);
							const marked = commits
								.filter(
									(c) =>
										sameKey(c.key, boundariesSpace, f.subject) &&
										(c.value as { erasedAt?: unknown } | undefined)?.erasedAt !== undefined,
								)
								.map((c) => c.version);
							if (passedOn && marked.length > 0)
								expect(passedOn.version).toBeLessThan(Math.min(...marked));
						}
					}
				},
			),
			{ seed, numRuns: runs },
		);
	} finally {
		vi.useRealTimers();
	}
}, 120_000);
