import { AsyncLocalStorage } from "node:async_hooks";
import { assemble, contract, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Json, type Key, type Space, type Store, spaces, store } from "@mod/store";
import { simulatedStore } from "@mod/store/testing";
import fc from "fast-check";
import { expect, it } from "vitest";
import { type Next, type Place, pairedRecordsAcross, recordsIn } from "../../records.ts";

// The scheduling and the commit order below are this file's own until store's `./testing` offers a
// plain hook for both (after G); then they move there and the version reading goes.

const guarantees = ["no-eviction", "durable", "replicated"] as const;
const left: Space = { name: "ledger-left", guarantees: [...guarantees] };
const right: Space = { name: "ledger-right", guarantees: [...guarantees] };
const opened = contract<Store>("test.store");
const accounts = [
	{ space: left, key: "a1" },
	{ space: left, key: "a2" },
	{ space: right, key: "b1" },
	{ space: right, key: "b2" },
] as const;
const opening = 10;

/** Bytes from a generated seed (xorshift32): the marks that settle resends, the same on every replay. */
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

/**
 * A write the store committed, with the version it minted. Commit order from `simulatedStore`'s one
 * version counter; the Store contract gives versions no order, so `countedUp` checks it each step.
 */
interface Commit {
	readonly version: number;
	readonly by: number | undefined;
	readonly key: Key;
}

function commitsOf(calls: readonly Call[]): Commit[] {
	return calls.flatMap((call): Commit[] => {
		const { op, args, answer, by } = call;
		if ((op === "putIfAbsent" || op === "replaceIf") && answer?.kind === "written") {
			return [{ version: Number(answer.version), by, key: args[0] as Key }];
		}
		if ((op === "batchAcross" || op === "batch") && answer?.kind === "committed") {
			const writes = args[1] as readonly { key: Key }[];
			return (answer.versions ?? []).flatMap((v, i) =>
				v === null ? [] : [{ version: Number(v), by, key: (writes[i] as { key: Key }).key }],
			);
		}
		return [];
	});
}

const keyOf = (key: Key) => `${key.space.name}/${key.partition}/${key.name}`;
const isRecord = (key: Key, space: Space, partition: string) =>
	key.space.name === space.name && key.partition === partition && key.name === "record";

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

type Op =
	| {
			readonly kind: "transfer";
			readonly from: number;
			readonly to: number;
			readonly amount: number;
	  }
	| { readonly kind: "guarded" }
	| { readonly kind: "stop" }
	| { readonly kind: "touch"; readonly account: number };
type Step =
	| Op
	| { readonly kind: "together"; readonly ops: readonly Op[] }
	| { readonly kind: "fault"; readonly fault: "Lr" | "F" | "C" };

const account = fc.integer({ min: 0, max: accounts.length - 1 });
const op: fc.Arbitrary<Op> = fc.oneof(
	{
		arbitrary: fc
			.record({
				kind: fc.constant("transfer" as const),
				from: account,
				to: account,
				amount: fc.integer({ min: 1, max: 15 }),
			})
			.filter((t) => t.from !== t.to),
		weight: 4,
	},
	{ arbitrary: fc.record({ kind: fc.constant("guarded" as const) }), weight: 2 },
	{ arbitrary: fc.record({ kind: fc.constant("stop" as const) }), weight: 1 },
	{ arbitrary: fc.record({ kind: fc.constant("touch" as const), account }), weight: 2 },
);
const step: fc.Arbitrary<Step> = fc.oneof(
	{ arbitrary: op, weight: 4 },
	{
		arbitrary: fc.record({
			kind: fc.constant("together" as const),
			ops: fc.array(op, { minLength: 2, maxLength: 3 }),
		}),
		weight: 4,
	},
	// The narrow race: a guarded count, the stop it watches and a transfer, all at once, in any order.
	{
		arbitrary: fc
			.tuple(
				op.filter((o) => o.kind === "transfer"),
				fc.nat({ max: 5 }),
			)
			.map(([transfer, order]): Step => {
				const ops: Op[] = [{ kind: "guarded" }, { kind: "stop" }, transfer];
				const [first, second, third] = [
					[0, 1, 2],
					[0, 2, 1],
					[1, 0, 2],
					[1, 2, 0],
					[2, 0, 1],
					[2, 1, 0],
				][order] as [number, number, number];
				return { kind: "together", ops: [ops[first], ops[second], ops[third]] as Op[] };
			}),
		weight: 3,
	},
	{
		arbitrary: fc.record({
			kind: fc.constant("fault" as const),
			fault: fc.constantFrom("Lr" as const, "F" as const, "C" as const),
		}),
		weight: 1,
	},
);

/** Two spaces of one guarantee on a simulated store, each store call a point the scheduler orders. */
async function ledger(s: fc.Scheduler, seed: number) {
	const simulated = simulatedStore();
	const app = await assemble({
		modules: [
			simulated.module,
			defineModule({ name: "user", replicaSafe: true, takes: [store] }, (m) => [
				m.contribute(spaces).by(() => left),
				m.contribute(spaces).by(() => right),
				m.provide(opened).by((c) => c.get(store)),
			]),
		],
		config: kernelConfig(),
		runtime: quietRuntime({ clock: { now: () => 1_800_000_000_000 } }),
	});
	const inner = app.get(opened);
	const calls: Call[] = [];
	const operation = new AsyncLocalStorage<number>();
	// Each call noted with the operation it was made for; the store itself is as is.
	const noted = Object.fromEntries(
		(
			[
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
			] as const
		).flatMap((name) => {
			const f = (
				inner as unknown as Record<string, ((...a: unknown[]) => Promise<never>) | undefined>
			)[name];
			if (typeof f !== "function") return [];
			return [
				[
					name,
					async (...args: unknown[]) => {
						const call: Call = { by: operation.getStore(), op: name, args };
						calls.push(call);
						const answer = await f.apply(inner, args);
						call.answer = answer;
						return answer;
					},
				],
			];
		}),
	) as unknown as Store;
	let live = false;
	const arm = (hooks: "before" | "confirm", name: keyof Store, space: string) => {
		const at = hooks === "before" ? simulated.beforeNext : simulated.beforeConfirm;
		at(name, space, async () => {
			arm(hooks, name, space);
			if (live) await s.schedule(Promise.resolve(), `${hooks}:${name}:${space}`);
		});
	};
	for (const space of [left.name, right.name]) {
		for (const name of ["get", "putIfAbsent", "replaceIf", "batchAcross"] as const) {
			arm("before", name, space);
			if (name !== "get") arm("confirm", name, space);
		}
	}
	const random = seededRandom(seed);
	const placeOf = (space: Space): Place => ({ store: noted, space, random });
	const paired = pairedRecordsAcross<Json, Json>(
		placeOf(left),
		placeOf(right),
		"test",
		(where, reason) => {
			throw new Error(`${where}: ${reason}`);
		},
	);
	const records = { left: recordsIn<Json>(placeOf(left)), right: recordsIn<Json>(placeOf(right)) };
	for (const a of accounts) {
		await (a.space === left ? records.left : records.right).create(a.key, opening, "endless");
	}
	await records.left.create("moves", 0, "endless");
	await records.left.create("guarded", 0, "endless");
	const scheduled = async <T>(run: () => Promise<T>) => {
		live = true;
		try {
			return await s.waitFor(run());
		} finally {
			live = false;
		}
	};
	const raw = (space: Space, partition: string) => inner.get({ space, partition, name: "record" });
	return {
		simulated,
		paired,
		records,
		calls,
		raw,
		scheduled,
		operation,
	};
}

const runs = Number(process.env.FC_RUNS ?? 200);
const seed = Number(process.env.FC_SEED ?? 20261111);

it("changes records of two spaces as one under any order of their store calls: every change applies once and whole, and none applies on a watched record that changed before it committed", async () => {
	await fc.assert(
		fc.asyncProperty(
			fc.scheduler(),
			fc.integer(),
			fc.array(step, { maxLength: 12 }),
			async (s, randomSeed, steps) => {
				const l = await ledger(s, randomSeed);
				let ids = 0;
				const answered = { moved: 0, counted: 0, unknownMoves: 0, unknownCounts: 0 };
				const counted: number[] = [];

				const exec = async (o: Op) => {
					const id = ++ids;
					const run = async () => {
						switch (o.kind) {
							case "transfer": {
								const from = accounts[o.from] as (typeof accounts)[number];
								const to = accounts[o.to] as (typeof accounts)[number];
								const firstKeys = [from, to].filter((a) => a.space === left).map((a) => a.key);
								const secondKeys = [from, to].filter((a) => a.space === right).map((a) => a.key);
								const keys = { first: [...firstKeys, "moves"], second: secondKeys };
								const changed = await l.paired.changeRecords(keys, {
									decide: (read) => {
										const value = (a: (typeof accounts)[number]) => {
											const at =
												a.space === left ? firstKeys.indexOf(a.key) : secondKeys.indexOf(a.key);
											return (a.space === left ? read.first[at] : read.second[at]) as number;
										};
										const moves = read.first[firstKeys.length] as number;
										if (value(from) < o.amount) return {};
										const next = (a: (typeof accounts)[number]): Next<Json> => ({
											value: value(a) + (a === from ? -o.amount : o.amount),
										});
										return {
											first: [
												...firstKeys.map((k) =>
													next(accounts.find((a) => a.key === k) as (typeof accounts)[number]),
												),
												{ value: moves + 1 },
											],
											second: secondKeys.map((k) =>
												next(accounts.find((a) => a.key === k) as (typeof accounts)[number]),
											),
										};
									},
								});
								const moves = changed.first[firstKeys.length];
								return moves?.after !== moves?.before ? "moved" : "short";
							}
							case "guarded": {
								const changed = await l.paired.changeRecords(
									{ first: ["guarded"], second: [] },
									{
										watch: () => ({ second: ["stop"] }),
										decide: (read) =>
											read.second[0] === undefined
												? { first: [{ value: (read.first[0] as number) + 1 }] }
												: {},
									},
								);
								const [guarded] = changed.first;
								return guarded?.after !== guarded?.before ? "counted" : "stopped";
							}
							case "stop":
								return l.records.right.create("stop", true, "endless");
							case "touch": {
								const a = accounts[o.account] as (typeof accounts)[number];
								return (a.space === left ? l.records.left : l.records.right).change(a.key, (v) => ({
									value: v,
								}));
							}
						}
					};
					try {
						const answer = await l.operation.run(id, run);
						if (answer === "moved") answered.moved++;
						if (answer === "counted") {
							answered.counted++;
							counted.push(id);
						}
					} catch (error) {
						if (!isUnavailable(error)) throw error;
						if (o.kind === "transfer") answered.unknownMoves++;
						if (o.kind === "guarded") answered.unknownCounts++;
					}
				};

				for (const st of steps) {
					switch (st.kind) {
						case "together":
							await l.scheduled(() => Promise.all(st.ops.map(exec)));
							break;
						case "fault":
							if (st.fault === "Lr") l.simulated.loseNextReply();
							if (st.fault === "F") await l.simulated.failover();
							if (st.fault === "C") await l.simulated.restart();
							break;
						default:
							await l.scheduled(() => exec(st));
					}

					// Whole: no transfer creates or loses a unit, and none overdraws.
					const balances = await Promise.all(
						accounts.map(async (a) => (await l.raw(a.space, a.key)).entry?.value as number),
					);
					expect(
						balances.reduce((sum, b) => sum + b, 0),
						`balances ${balances.join(",")}`,
					).toBe(accounts.length * opening);
					for (const b of balances) expect(b).toBeGreaterThanOrEqual(0);
					// Once: each counter counts every answered change, and at most the ones left unknown besides.
					const moves = (await l.raw(left, "moves")).entry?.value as number;
					expect(moves).toBeGreaterThanOrEqual(answered.moved);
					expect(moves).toBeLessThanOrEqual(answered.moved + answered.unknownMoves);
					const guarded = (await l.raw(left, "guarded")).entry?.value as number;
					expect(guarded).toBeGreaterThanOrEqual(answered.counted);
					expect(guarded).toBeLessThanOrEqual(answered.counted + answered.unknownCounts);
					// Watched: every guarded count committed before the stop it watched was written.
					const commits = commitsOf(l.calls);
					const stop = commits.find((c) => isRecord(c.key, right, "stop"));
					if (stop) {
						for (const c of commits.filter((c) => isRecord(c.key, left, "guarded"))) {
							expect(c.version, `count by operation ${c.by} after the stop`).toBeLessThan(
								stop.version,
							);
						}
					}
					const held = new Map<string, string | undefined>();
					for (const a of accounts)
						held.set(
							keyOf({ space: a.space, partition: a.key, name: "record" }),
							(await l.raw(a.space, a.key)).entry?.version,
						);
					countedUp(commits, held);
				}
			},
		),
		{ seed, numRuns: runs },
	);
}, 120_000);
