/**
 * consent-store's half of erasing a subject's consent: its ports, over subject-records and records
 * on a simulated store, two instances at once. Under any order of their store calls, with lost
 * replies, failovers, restarts and the clock moving on, once erasing a subject has answered:
 * - no read answers its grants, on either instance, and the store itself holds none of its grants
 *   or bucket entries, only its tombstone;
 * - no grant or ask of it commits after its tombstone, however the write raced the erasure or was
 *   sent again, and a save answers `erased` only once its erasure has begun;
 * - an ask from before ends by the `until` the erasure answered;
 * - another subject's grants and asks are kept as they were.
 * What consent does with `erased` (refusing, answering no session, recording nothing) is consent's,
 * held by its own tests.
 *
 * Commit order comes from `simulatedStore`'s one version counter, which the Store contract does not
 * promise: `countedUp` checks it each step. That and the scheduling are this file's own until
 * store's `./testing` offers a plain hook for both (after G).
 *
 * Per-PR runs are fixed: FC_SEED (default 20261111) and FC_RUNS (default 200).
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { createHash } from "node:crypto";
import {
	askLifetimeMaxMs,
	askStore,
	grantStore,
	type RecordStore,
	type StoredAsk,
	type StoredGrant,
} from "@mod/consent";
import { assemble, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Key, type Space, type Store, store, storeControl } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import fc from "fast-check";
import { expect, it, vi } from "vitest";
import wiring from "../src/module.ts";

const seed = Number(process.env.FC_SEED ?? 20261111);
const numRuns = Number(process.env.FC_RUNS ?? 200);

const grantsSpace = "consent-store.grants";
const asksSpace = "consent-store.asks";
const indexOf = (space: string) => `${space}.index`;
const subjects = ["alice", "bob"] as const;
type Subject = (typeof subjects)[number];
const clients = ["c1", "c2"] as const;
const hostNow = 1_800_000_000_000;

/** A subject's part of a space's index, as subject-records names it. */
const part = (space: string, subject: string) =>
	`1.${createHash("sha256").update(`${space}\n${subject}`).digest("base64url")}`;
const buckets = Array.from({ length: 16 }, (_, i) => `m${i.toString(16)}`);
/** consent's key of a grant: one per subject and client. */
const grantKey = (subject: string, client: string) => JSON.stringify([subject, client]);
const askKey = (subject: string, n: number) => `ask-${subject}-${n}`;

/** Bytes from a generated seed (xorshift32): the runtime's randomness, the same on every replay. */
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
 * A write the store committed, with the version it minted and whether it created its key. Commit
 * order from `simulatedStore`'s one version counter; the Store contract gives versions no order,
 * so `countedUp` checks it each step.
 */
interface Commit {
	readonly version: number;
	readonly by: number | undefined;
	readonly key: Key;
	readonly put: unknown;
	readonly created: boolean;
}
type Condition = { readonly key: Key; readonly absent?: boolean };
const keyOf = (key: Key) => `${key.space.name}/${key.partition}/${key.name}`;

function commitsOf(calls: readonly Call[]): Commit[] {
	return calls.flatMap((call): Commit[] => {
		const { op, args, answer, by } = call;
		if ((op === "putIfAbsent" || op === "replaceIf") && answer?.kind === "written") {
			const put = op === "putIfAbsent" ? args[1] : args[2];
			const key = args[0] as Key;
			return [{ version: Number(answer.version), by, key, put, created: op === "putIfAbsent" }];
		}
		if ((op === "batch" || op === "batchAcross") && answer?.kind === "committed") {
			const [conditions, writes] = args as [Condition[], { key: Key; put?: unknown }[]];
			return (answer.versions ?? []).flatMap((v, i) => {
				const w = writes[i] as { key: Key; put?: unknown };
				if (v === null || !("put" in w)) return [];
				const created = conditions.some((c) => c.absent && keyOf(c.key) === keyOf(w.key));
				return [{ version: Number(v), by, key: w.key, put: w.put, created }];
			});
		}
		return [];
	});
}

/** Whether the versions still count up: integers, each minted for one key, none held below one committed. */
function countedUp(commits: readonly Commit[], held: ReadonlyMap<string, string | undefined>) {
	const minted = new Map<number, string>();
	for (const c of commits) {
		expect(Number.isInteger(c.version), "a version that is no count").toBe(true);
		const first = minted.get(c.version) ?? keyOf(c.key);
		expect(keyOf(c.key), `version ${c.version} minted for ${first} and again`).toBe(first);
		minted.set(c.version, first);
	}
	for (const [where, version] of held) {
		const committed = commits.filter((c) => keyOf(c.key) === where).map((c) => c.version);
		if (committed.length === 0 || version === undefined) continue;
		expect(
			Number(version),
			`${where} holds a version below one committed to it`,
		).toBeGreaterThanOrEqual(Math.max(...committed));
	}
}

/** The subject a stored grant (an envelope) or ask (raw, as the test writes it) names. */
const subjectIn = (put: unknown) =>
	(put as { subject?: unknown } | undefined)?.subject as string | undefined;

type Instance = 0 | 1;
type Act =
	| {
			readonly kind: "grant";
			readonly at: Instance;
			readonly subject: Subject;
			readonly client: number;
	  }
	| {
			readonly kind: "widen";
			readonly at: Instance;
			readonly subject: Subject;
			readonly client: number;
	  }
	| {
			readonly kind: "ask";
			readonly at: Instance;
			readonly subject: Subject;
			readonly n: number;
			readonly lifetimeMs: number;
	  }
	| {
			readonly kind: "answer";
			readonly at: Instance;
			readonly subject: Subject;
			readonly n: number;
	  }
	| { readonly kind: "erase"; readonly at: Instance; readonly subject: Subject };
type Step =
	| Act
	| { readonly kind: "together"; readonly acts: readonly Act[] }
	// {fault:Lx}: every answer to its writes is lost, the writes applied or not.
	| { readonly kind: "lx"; readonly act: Act }
	| { readonly kind: "fault"; readonly fault: "Lr" | "F" | "C" }
	| { readonly kind: "clock"; readonly ms: number };

const instance = fc.constantFrom<Instance>(0, 1);
const subject = fc.constantFrom<Subject>(...subjects);
const client = fc.nat({ max: clients.length - 1 });
const n = fc.nat({ max: 2 });
const writing: fc.Arbitrary<Act> = fc.oneof(
	{
		arbitrary: fc.record({ kind: fc.constant("grant" as const), at: instance, subject, client }),
		weight: 3,
	},
	{
		arbitrary: fc.record({ kind: fc.constant("widen" as const), at: instance, subject, client }),
		weight: 2,
	},
	{
		arbitrary: fc.record({
			kind: fc.constant("ask" as const),
			at: instance,
			subject,
			n,
			lifetimeMs: fc.integer({ min: 1000, max: askLifetimeMaxMs }),
		}),
		weight: 2,
	},
	{
		arbitrary: fc.record({ kind: fc.constant("answer" as const), at: instance, subject, n }),
		weight: 1,
	},
);
const erase: fc.Arbitrary<Act> = fc.record({
	kind: fc.constant("erase" as const),
	at: instance,
	subject,
});
/** An erasure among writes for the same subject: the race this property is for. */
const raced: fc.Arbitrary<Step> = fc
	.tuple(subject, erase, fc.array(writing, { minLength: 1, maxLength: 3 }), fc.nat({ max: 3 }))
	.map(([s, e, ws, at]) => {
		const theirs = ws.map((w) => ({ ...w, subject: s }));
		const acts = [...theirs.slice(0, at), { ...e, subject: s }, ...theirs.slice(at)];
		return { kind: "together" as const, acts };
	});
const step: fc.Arbitrary<Step> = fc.oneof(
	{ arbitrary: writing, weight: 4 },
	{ arbitrary: erase, weight: 1 },
	{ arbitrary: raced, weight: 3 },
	{
		arbitrary: fc.record({
			kind: fc.constant("together" as const),
			acts: fc.array(fc.oneof(writing, erase), { minLength: 2, maxLength: 3 }),
		}),
		weight: 2,
	},
	{
		arbitrary: fc.record({ kind: fc.constant("lx" as const), act: fc.oneof(writing, erase) }),
		weight: 1,
	},
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
			ms: fc.integer({ min: 1, max: 2 * askLifetimeMaxMs }),
		}),
		weight: 1,
	},
);

/** Two instances of consent-store over one simulated store, records indexed, each store call a point the scheduler orders. */
async function deployment(s: fc.Scheduler, from: number) {
	const simulated = simulatedStore();
	simulated.mark("subject-records.phase", "indexed");
	const command = new AsyncLocalStorage<number>();
	const calls: Call[] = [];
	let live = false;
	const lostFor = new Set<number>();
	// Each hook arms the next before it waits, so every call of the operation in the space is a point.
	const arm = (hooks: "before" | "confirm", op: keyof Store, space: string) => {
		const at = hooks === "before" ? simulated.beforeNext : simulated.beforeConfirm;
		at(op, space, async () => {
			arm(hooks, op, space);
			const id = command.getStore();
			if (hooks === "before" && id !== undefined && lostFor.has(id) && op !== "get") {
				simulated.loseNextReply();
			}
			if (live) await s.schedule(Promise.resolve(), `${id}:${hooks}:${op}:${space}`);
		});
	};
	for (const space of [grantsSpace, indexOf(grantsSpace), asksSpace, indexOf(asksSpace)]) {
		for (const op of ["get", "putIfAbsent", "replaceIf", "batch", "batchAcross"] as const) {
			arm("before", op, space);
			if (op !== "get") arm("confirm", op, space);
		}
	}
	const runtime = quietRuntime({ clock: { now: () => hostNow }, random: seededRandom(from) });
	const base = await assemble({
		modules: [simulated.module, wiring],
		config: kernelConfig(),
		runtime,
	});
	const shared = defineModule({ name: "store", replicaSafe: true, takes: [] }, (m) => [
		m.provide(store).by(() => noted(base.get(store), calls, command)),
		m.provide(storeControl).by(() => base.get(storeControl)),
	]);
	const instances = await Promise.all(
		[0, 1].map(async () => {
			const app = await assemble({ modules: [shared, wiring], config: kernelConfig(), runtime });
			return {
				grants: app.get(grantStore) as RecordStore<StoredGrant>,
				asks: app.get(askStore) as RecordStore<StoredAsk>,
			};
		}),
	);
	const inner = base.get(store);
	const spaceOf = (name: string): Space => ({ name, guarantees: [] });
	const raw = async (space: string, partition: string) =>
		(await inner.get({ space: spaceOf(space), partition, name: "record" })).entry;
	/** Every record of a space, as the store itself holds it. */
	const held = async (space: string) => {
		const found: { partition: string; value: unknown; expiresAt: number | null }[] = [];
		let cursor: string | undefined;
		do {
			const page = await inner.scan(spaceOf(space), cursor);
			for (const key of page.keys) {
				if (key.name !== "record") continue;
				const { entry } = await inner.get(key);
				if (entry)
					found.push({ partition: key.partition, value: entry.value, expiresAt: entry.expiresAt });
			}
			cursor = page.cursor;
		} while (cursor !== undefined);
		return found;
	};
	// Runs until `go` settles: a scheduled store call where one waits, else the next of records'
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
				if (s.count() > 0) await s.waitNext(1);
				else if (vi.getTimerCount() > 0) await vi.advanceTimersToNextTimerAsync();
				else await new Promise<void>((resolve) => setImmediate(resolve));
			}
			return await running;
		} finally {
			live = false;
		}
	};
	return { simulated, command, calls, instances, raw, held, scheduled, lostFor };
}

it("erases a subject's consent through consent-store under any order of two instances' store calls: no grant read or stored after, none written after its tombstone, an old ask ending by the erasure's until, and nothing of another subject touched", async () => {
	vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
	try {
		await fc.assert(
			fc.asyncProperty(
				fc.scheduler(),
				fc.integer(),
				fc.array(step, { maxLength: 10 }),
				async (s, from, steps) => {
					const d = await deployment(s, from);
					let ids = 0;
					let shifted = 0;
					/** Subjects an erasure has begun for, and those whose grants it answered erased. */
					const begun = new Set<string>();
					const erased = new Set<string>();
					/** The `until` each subject's asks were answered fenced to. */
					const until = new Map<string, number>();
					/** Grants answered created, of subjects no erasure has begun for when it answered. */
					const created = new Set<string>();
					/** Asks answered created, of subjects no erasure has begun for: whose, and their end on the store clock. */
					const asked = new Map<string, { readonly who: string; readonly end: number }>();

					const exec = async (a: Act, set?: (id: number) => void) => {
						const id = ++ids;
						set?.(id);
						const { grants, asks } = d.instances[a.at] as (typeof d.instances)[number];
						const run = async () => {
							switch (a.kind) {
								case "grant": {
									const key = grantKey(a.subject, clients[a.client] as string);
									const value = { format: 2, range: ["read"] } as unknown as StoredGrant;
									const saved = await grants.save(key, value, "endless", a.subject);
									// `erased` only once its erasure has begun: the race, never another cause.
									if (saved === "erased")
										expect(begun.has(a.subject), `${key} erased unasked`).toBe(true);
									if (saved === "created" && !begun.has(a.subject)) created.add(key);
									return;
								}
								case "widen": {
									const key = grantKey(a.subject, clients[a.client] as string);
									await grants.update(key, (held) => ({
										value: {
											...(held as object),
											range: ["read", `w${id}`],
										} as unknown as StoredGrant,
									}));
									return;
								}
								case "ask": {
									const value = { subject: a.subject, n: a.n } as unknown as StoredAsk;
									const saved = await asks.save(
										askKey(a.subject, a.n),
										value,
										a.lifetimeMs,
										a.subject,
									);
									if (saved === "erased")
										expect(begun.has(a.subject), "an ask erased unasked").toBe(true);
									if (saved === "created" && !begun.has(a.subject)) {
										// The store clock stands between steps: the ask ends this far on from now.
										const end = hostNow + shifted + a.lifetimeMs;
										asked.set(askKey(a.subject, a.n), { who: a.subject, end });
									}
									return;
								}
								case "answer":
									await asks.update(askKey(a.subject, a.n), (held) => ({
										value: { ...(held as object), answer: id } as unknown as StoredAsk,
									}));
									return;
								case "erase": {
									begun.add(a.subject);
									const signal = new AbortController().signal;
									// As consent's eraser: grants, then asks.
									const g = await grants.erase?.(a.subject, signal);
									const k = await asks.erase?.(a.subject, signal);
									if ((g as { kind?: string } | undefined)?.kind === "erased")
										erased.add(a.subject);
									const fenced = k as { kind?: string; until?: number } | undefined;
									if (fenced?.kind === "fenced" && fenced.until !== undefined) {
										until.set(a.subject, Math.max(until.get(a.subject) ?? 0, fenced.until));
									}
									return;
								}
							}
						};
						try {
							await d.command.run(id, run);
						} catch (error) {
							if (!isUnavailable(error)) throw error;
						}
					};

					for (const st of steps) {
						switch (st.kind) {
							case "together":
								await d.scheduled(() => Promise.all(st.acts.map((a) => exec(a))));
								break;
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
								shifted += st.ms;
								break;
							default:
								await d.scheduled(() => exec(st));
						}

						const commits = commitsOf(d.calls);
						/** Each subject's tombstone in a space, by the version that wrote it. */
						const tombOf = (space: string, who: string) =>
							commits.find(
								(c) => keyOf(c.key) === `${indexOf(space)}/${part(space, who)}.tomb/record`,
							);

						for (const who of subjects) {
							// Nothing of the subject commits after its tombstone: no grant, no entry, no new ask.
							const grantsTomb = tombOf(grantsSpace, who);
							if (grantsTomb) {
								for (const c of commits) {
									const late = c.version > grantsTomb.version;
									if (late && c.key.space.name === grantsSpace && subjectIn(c.put) === who) {
										expect.fail(
											`a grant of ${who} committed after its tombstone, by command ${c.by}`,
										);
									}
									if (
										late &&
										c.key.space.name === indexOf(grantsSpace) &&
										c.key.partition.startsWith(`${part(grantsSpace, who)}.m`) &&
										Array.isArray(c.put) &&
										c.put.length > 0
									) {
										expect.fail(
											`${who}'s bucket listed a grant after its tombstone, by command ${c.by}`,
										);
									}
								}
							}
							const asksTomb = tombOf(asksSpace, who);
							if (asksTomb) {
								for (const c of commits) {
									if (c.key.space.name !== asksSpace || !c.created || subjectIn(c.put) !== who)
										continue;
									expect(c.version, `an ask of ${who} created after its tombstone`).toBeLessThan(
										asksTomb.version,
									);
								}
							}
						}

						for (const who of erased) {
							// No read answers its grants, on either instance.
							for (const c of clients) {
								for (const at of d.instances) {
									expect(
										await at.grants.read(grantKey(who, c)),
										`${who}/${c} read after erasure`,
									).toBeUndefined();
								}
							}
							// The store itself holds none of its grants or entries: its tombstone alone.
							const left = (await d.held(grantsSpace)).filter((r) => subjectIn(r.value) === who);
							expect(
								left.map((r) => r.partition),
								`${who}'s grants stored after erasure`,
							).toEqual([]);
							for (const b of buckets) {
								const entry = await d.raw(indexOf(grantsSpace), `${part(grantsSpace, who)}.${b}`);
								expect(entry?.value ?? [], `${who}'s bucket ${b} after erasure`).toEqual([]);
							}
							expect(
								await d.raw(indexOf(grantsSpace), `${part(grantsSpace, who)}.tomb`),
							).not.toBeNull();
						}
						// An ask from before the erasure ends by the `until` answered.
						for (const [who, end] of until) {
							for (const r of await d.held(asksSpace)) {
								if (subjectIn(r.value) !== who) continue;
								expect(
									r.expiresAt ?? Number.POSITIVE_INFINITY,
									`an ask of ${who} outliving ${end}`,
								).toBeLessThanOrEqual(end);
							}
						}
						// Another subject's grants are kept: each created before any erasure of it still reads.
						for (const key of created) {
							const [who] = JSON.parse(key) as [string];
							if (begun.has(who)) continue;
							expect(
								await (d.instances[0] as (typeof d.instances)[number]).grants.read(key),
								`${key} lost`,
							).toBeDefined();
						}
						// And its asks: each created before any erasure of it reads until its own end.
						for (const [key, { who, end }] of asked) {
							if (begun.has(who) || hostNow + shifted >= end) continue;
							expect(
								await (d.instances[1] as (typeof d.instances)[number]).asks.read(key),
								`${key} lost before its end`,
							).toBeDefined();
						}
						const heldVersions = new Map<string, string | undefined>();
						for (const who of subjects) {
							for (const space of [grantsSpace, asksSpace]) {
								const tomb = await d.raw(indexOf(space), `${part(space, who)}.tomb`);
								heldVersions.set(
									`${indexOf(space)}/${part(space, who)}.tomb/record`,
									tomb?.version,
								);
							}
						}
						countedUp(commits, heldVersions);
					}
					expect(shifted).toBeGreaterThanOrEqual(0);
				},
			),
			{ seed, numRuns },
		);
	} finally {
		vi.useRealTimers();
	}
}, 300_000);
