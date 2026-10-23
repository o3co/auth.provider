import { describe, expect, it } from "vitest";
import type { z } from "zod";
import {
	type Json,
	type Key,
	mutate,
	type Space,
	type Store,
	type Version,
	type WriteOptions,
} from "./contract.ts";
import type { section } from "./section.ts";

export { type SimulatedStore, simulatedStore } from "./simulated.ts";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** For tests' set-up: writes a key whatever it holds, on the version read or if absent, again on a lost race. */
export async function overwrite(s: Store, key: Key, value: Json, options: WriteOptions) {
	for (let attempt = 0; attempt < 8; attempt++) {
		const { entry } = await s.get(key);
		const answer = entry
			? await s.replaceIf(key, entry.version, value, options)
			: await s.putIfAbsent(key, value, options);
		if (answer.kind === "written" || answer.kind === "late" || answer.kind === "reused") {
			return answer;
		}
	}
	throw new Error("overwrite: the key kept moving");
}

/** The spaces the contract tests use; a harness declares them when it opens a store. */
export const contractSpaces: readonly Space[] = Object.freeze([
	{ name: "contract", guarantees: [] },
	{ name: "contract-replicated", guarantees: ["replicated"] },
	{ name: "contract-confirmed", guarantees: ["replicated", "confirmed-reads"] },
	// The guarantees of the first, so a batch across spaces can join the two.
	{ name: "contract-twin", guarantees: [] },
]);

export interface StoreHarness {
	/** A store over a fresh, empty namespace. */
	open(): Promise<Store>;
	/** Another connection to the same data as `store`. */
	peer(store: Store): Promise<Store>;
	/** For implementations that replicate: stop replicas from acknowledging until the returned undo runs. */
	stopReplicas?(): Promise<() => Promise<void>>;
	/** For implementations over a network: drop the reply to the next command sent through `store`. */
	loseNextReply?(store: Store): Promise<void>;
	/** For implementations with a server: restart it, keeping what it persisted. */
	restart?(): Promise<void>;
	/**
	 * For implementations that replicate: promote a replica in place of the primary while the
	 * replica lacks the latest writes (it may be stopped beforehand); the returned undo restores
	 * the old roles with replicas running.
	 */
	failover?(): Promise<() => Promise<void>>;
}

/** The first answer `attempt` gives without rejecting, trying `tries` times 100 ms apart. */
async function eventually<T>(attempt: () => Promise<T>, tries: number): Promise<T | undefined> {
	for (let i = 0; i < tries; i++) {
		const answer = await attempt().catch(async () => {
			await sleep(100);
			return undefined;
		});
		if (answer !== undefined) return answer;
	}
	return undefined;
}

/** Reads until the store clock passes `at`, and checks that presence ends exactly at `at`. */
async function expectPresentUntil(
	at: number,
	read: () => Promise<{ now: number; present: boolean }>,
): Promise<void> {
	const seen: [number, boolean][] = [];
	for (let i = 0; i < 400; i++) {
		const { now, present } = await read();
		seen.push([now, present]);
		if (now > at) break;
		await sleep(1);
	}
	for (const [time, present] of seen) expect([time, present]).toEqual([time, time < at]);
	expect(seen.some(([time]) => time >= at)).toBe(true);
}

/** `count` calls started together, alternating between two connections to the same data. */
const race = <T>(
	count: number,
	[s, t]: readonly [Store, Store],
	run: (store: Store, i: number) => Promise<T>,
) => Promise.all(Array.from({ length: count }, (_, i) => run(i % 2 ? s : t, i)));

const versionOf = (answer: { kind: string; version?: Version }): Version => {
	if (answer.kind !== "written" || answer.version === undefined)
		throw new Error(`not written: ${answer.kind}`);
	return answer.version;
};

/** The store contract, run against any implementation. */
export function storeContract(name: string, harness: StoreHarness): void {
	const [space, replicated, confirmed, twin] = contractSpaces as [Space, Space, Space, Space];
	let n = 0;
	/** Keys of `target` in a partition no other test uses. */
	const fresh =
		(target: Space = space, partition = `p${++n}`) =>
		(name: string): Key => ({ space: target, partition, name });
	const never = { expiry: { kind: "never" } } as const;
	const both = async () => {
		const s = await harness.open();
		return [s, await harness.peer(s)] as const;
	};

	describe(`store contract: ${name}`, () => {
		describe("reads and writes", () => {
			it("reads back what it wrote with a version and the store time", async () => {
				const s = await harness.open();
				const k = fresh()("a");
				expect((await s.get(k)).entry).toBeNull();
				const version = versionOf(await overwrite(s, k, { x: [1, "y"] }, never));
				const r = await s.get(k);
				expect(r.entry).toEqual({ value: { x: [1, "y"] }, version, expiresAt: null });
				expect(r.now).toBeGreaterThan(0);
			});

			it("tells the present time of the clock it judges expiry by", async () => {
				const s = await harness.open();
				const before = (await s.get(fresh()("probe"))).now;
				const told = await s.now();
				const after = (await s.get(fresh()("probe"))).now;
				expect(told).toBeGreaterThanOrEqual(before);
				expect(told).toBeLessThanOrEqual(after);
			});

			it("writes if absent and otherwise reports the remaining time", async () => {
				const s = await harness.open();
				const k = fresh()("a");
				expect((await s.putIfAbsent(k, 1, { expiry: { kind: "after", ms: 10_000 } })).kind).toBe(
					"written",
				);
				const again = await s.putIfAbsent(k, 2, never);
				expect(
					again.kind === "exists" && again.remainingMs !== null && again.remainingMs <= 10_000,
				).toBe(true);
			});

			it("replaces and removes only on the version or value expected", async () => {
				const s = await harness.open();
				const k = fresh()("a");
				const version = versionOf(await overwrite(s, k, "one", never));
				expect((await s.replaceIf(k, `${version}x`, "x", never)).kind).toBe("conflict");
				expect((await s.replaceIf(k, version, "two", never)).kind).toBe("written");
				expect((await s.removeIf(k, { value: "one" })).kind).toBe("conflict");
				const removed = await s.removeIf(k, { value: "two" });
				expect(removed.kind === "removed" && removed.old.value).toBe("two");
				expect((await s.replaceIf(fresh()("none"), version, "x", never)).kind).toBe("missing");
			});

			it("commits a batch in one partition only when every condition holds", async () => {
				const s = await harness.open();
				const key = fresh();
				const version = versionOf(await overwrite(s, key("a"), 1, never));
				const lost = await s.batch(
					[
						{ key: key("a"), version },
						{ key: key("b"), absent: true },
						{ key: key("a"), version: `${version}x` },
					],
					[{ key: key("b"), put: 2, expiry: { kind: "never" } }],
				);
				expect(lost).toEqual({ kind: "conflict", index: 2 });
				expect((await s.get(key("b"))).entry).toBeNull();
				const won = await s.batch(
					[
						{ key: key("a"), version },
						{ key: key("b"), absent: true },
					],
					[
						{ key: key("a"), remove: true },
						{ key: key("b"), put: 2, expiry: { kind: "never" } },
					],
				);
				expect(won.kind).toBe("committed");
				expect([(await s.get(key("a"))).entry, (await s.get(key("b"))).entry?.value]).toEqual([
					null,
					2,
				]);
				await expect(
					s.batch(
						[],
						[
							{ key: fresh()("x"), remove: true },
							{ key: key("y"), remove: true },
						],
					),
				).rejects.toThrow();
			});

			it("returns values in canonical form, with object keys sorted", async () => {
				const s = await harness.open();
				const k = fresh()("doc");
				await overwrite(s, k, { b: 1, a: { d: 2, c: 3 } }, never);
				const value = (await s.get(k)).entry?.value as Record<string, Record<string, number>>;
				expect(Object.keys(value)).toEqual(["a", "b"]);
				expect(Object.keys(value.a ?? {})).toEqual(["c", "d"]);
			});

			it("removes the entry when a mutation decides to", async () => {
				const s = await harness.open();
				const k = fresh()("a");
				await overwrite(s, k, 1, never);
				expect(await mutate(s, k, () => ({ kind: "remove" }))).toEqual({
					kind: "done",
					value: null,
					version: null,
				});
				expect((await s.get(k)).entry).toBeNull();
			});

			it("answers a mutation that keeps with the entry, and reads again when a removal loses a race", async () => {
				const s = await harness.open();
				const key = fresh();
				const version = versionOf(await overwrite(s, key("a"), 1, never));
				expect(await mutate(s, key("a"), () => ({ kind: "keep" }))).toEqual({
					kind: "done",
					value: 1,
					version,
				});
				let runs = 0;
				const removed = await mutate(s, key("a"), (entry) => {
					runs += 1;
					// Another client rewrites the entry after the first read.
					if (runs === 1 && entry) void s.replaceIf(key("a"), entry.version, 2, never);
					return { kind: "remove" };
				});
				expect([removed.kind, runs]).toEqual(["done", 2]);
				expect((await s.get(key("a"))).entry).toBeNull();
			});
		});

		describe("versions", () => {
			it("never repeats a version, after a remove or after other keys of the partition expire", async () => {
				const s = await harness.open();
				const key = fresh();
				const seen = new Set<Version>();
				const first = versionOf(await overwrite(s, key("a"), 1, never));
				seen.add(first);
				await s.removeIf(key("a"), { value: 1 });
				seen.add(versionOf(await overwrite(s, key("a"), 1, never)));
				expect((await s.replaceIf(key("a"), first, 2, never)).kind).toBe("conflict");
				const kept = versionOf(await overwrite(s, key("long"), 1, never));
				seen.add(kept);
				for (let i = 0; i < 5; i++)
					seen.add(
						versionOf(await overwrite(s, key("short"), i, { expiry: { kind: "after", ms: 100 } })),
					);
				await sleep(300);
				for (let i = 0; i < 5; i++) seen.add(versionOf(await overwrite(s, key("short"), i, never)));
				expect(seen.size).toBe(13);
				expect((await s.replaceIf(key("long"), kept, 2, never)).kind).toBe("written");
			});

			it.runIf(harness.restart !== undefined)(
				"never repeats a version across a restart",
				async () => {
					const s = await harness.open();
					const k = fresh()("a");
					const before = [
						versionOf(await overwrite(s, k, 1, never)),
						versionOf(await overwrite(s, k, 2, never)),
					];
					await harness.restart?.();
					const written = await eventually(() => overwrite(s, k, 3, never), 100);
					const after = written && versionOf(written);
					expect(before).not.toContain(after);
					expect((await s.replaceIf(k, before[1] as Version, 4, never)).kind).toBe("conflict");
				},
				60_000,
			);

			it.runIf(harness.failover !== undefined)(
				"never repeats a version after a replica that missed writes is promoted",
				async () => {
					const s = await harness.open();
					const k = fresh()("a");
					const seen = [versionOf(await overwrite(s, k, 1, never))];
					await harness.stopReplicas?.();
					await overwrite(s, k, 2, never).catch(() => undefined);
					const unconfirmed = (await s.get(k)).entry?.version;
					if (unconfirmed) seen.push(unconfirmed);
					const undo = await harness.failover?.();
					try {
						const written = await eventually(() => overwrite(s, k, 3, never), 100);
						const after = written && versionOf(written);
						expect(after).toBeDefined();
						expect(seen).not.toContain(after);
					} finally {
						await undo?.();
					}
				},
				120_000,
			);

			it.runIf(harness.failover !== undefined)(
				"never repeats a version when the same replica is promoted again",
				async () => {
					const s = await harness.open();
					const k = fresh()("a");
					const seen = new Set<Version>([versionOf(await overwrite(s, k, 1, never))]);
					const promote = async () => {
						const undo = await harness.failover?.();
						try {
							const written = await eventually(() => overwrite(s, k, 2, never), 100);
							const after = written && versionOf(written);
							if (after === undefined) throw new Error("no write after the promotion");
							expect(seen.has(after)).toBe(false);
							seen.add(after);
						} finally {
							await undo?.();
						}
					};
					await promote();
					await promote();
				},
				240_000,
			);
		});

		describe("expiry", () => {
			it("expires entries on the store clock and keeps or extends expiry when asked", async () => {
				const s = await harness.open();
				const key = fresh();
				const soon = { expiry: { kind: "after", ms: 150 } } as const;
				await s.putIfAbsent(key("short"), 1, soon);
				const kept = versionOf(await s.putIfAbsent(key("kept"), 1, soon));
				const long = versionOf(await s.putIfAbsent(key("long"), 1, soon));
				const forever = versionOf(await s.putIfAbsent(key("forever"), 1, never));
				const ends = [
					(await s.get(key("short"))).entry?.expiresAt ?? 0,
					(await s.get(key("kept"))).entry?.expiresAt ?? 0,
				];
				// On the version written, so one landing past the expiry is refused, never a new entry.
				const rewrite = (name: string, version: Version, expiry: WriteOptions["expiry"]) =>
					s.replaceIf(key(name), version, 2, { expiry });
				if ((await rewrite("kept", kept, { kind: "keep" })).kind === "written") {
					expect((await s.get(key("kept"))).entry?.expiresAt).toBe(ends[1]);
				}
				const extended = await rewrite("long", long, { kind: "extend", ms: 5000 });
				expect((await rewrite("forever", forever, { kind: "extend", ms: 10 })).kind).toBe(
					"written",
				);
				// Until the store clock, not the caller's, is past both expiries.
				while ((await s.get(key("probe"))).now <= Math.max(...ends)) await sleep(25);
				expect((await s.get(key("short"))).entry).toBeNull();
				expect((await s.get(key("kept"))).entry).toBeNull();
				if (extended.kind === "written") expect((await s.get(key("long"))).entry?.value).toBe(2);
				expect((await s.get(key("forever"))).entry?.expiresAt).toBeNull();
			});

			it("holds an entry only while the store clock is before its expiry, reads and keep-writes alike", async () => {
				const s = await harness.open();
				const key = fresh();
				const { now } = await s.get(key("probe"));
				const at = now + 30;
				await overwrite(s, key("a"), 1, { expiry: { kind: "at", at } });
				await expectPresentUntil(at, async () => {
					const read = await s.get(key("a"));
					return { now: read.now, present: read.entry !== null };
				});
				const { now: later } = await s.get(key("probe"));
				await overwrite(s, key("b"), 1, { expiry: { kind: "at", at: later } });
				expect((await s.get(key("b"))).entry).toBeNull();
			});

			it("expires at the time given, and treats expired entries as absent everywhere", async () => {
				const s = await harness.open();
				const key = fresh();
				const { now } = await s.get(key("x"));
				await overwrite(s, key("at"), 1, { expiry: { kind: "at", at: now + 150 } });
				expect((await s.get(key("at"))).entry?.value).toBe(1);
				const version = versionOf(
					await overwrite(s, key("gone"), 1, { expiry: { kind: "after", ms: 150 } }),
				);
				await overwrite(s, key("w"), 1, { expiry: { kind: "after", ms: 150 } });
				await sleep(400);
				expect((await s.get(key("at"))).entry).toBeNull();
				expect((await s.take(key("gone"))).kind).toBe("missing");
				expect((await s.replaceIf(key("gone"), version, 2, never)).kind).toBe("missing");
				expect((await s.removeIf(key("w"), { value: 1 })).kind).toBe("missing");
				expect((await s.putIfAbsent(key("w"), 2, never)).kind).toBe("written");
			});

			it("drops a write whose expiry has already come, and compares values regardless of key order", async () => {
				const s = await harness.open();
				const key = fresh();
				const { now } = await s.get(key("x"));
				expect(
					(await s.putIfAbsent(key("past"), 1, { expiry: { kind: "at", at: now } })).kind,
				).toBe("written");
				expect((await s.get(key("past"))).entry).toBeNull();
				await overwrite(s, key("doc"), { a: 1, b: 2 }, never);
				expect((await s.removeIf(key("doc"), { value: { b: 2, a: 1 } })).kind).toBe("removed");
			});
		});

		describe("deadlines and idempotency marks", () => {
			it("refuses putIfAbsent, replaceIf, removeIf, batch and mutate past their deadline on the store clock", async () => {
				const s = await harness.open();
				const key = fresh();
				const version = versionOf(await overwrite(s, key("a"), 1, never));
				const { now } = await s.get(key("a"));
				const late = { deadline: now - 1 };
				expect((await s.putIfAbsent(key("b"), 1, { ...never, ...late })).kind).toBe("late");
				expect((await s.replaceIf(key("a"), version, 2, { ...never, ...late })).kind).toBe("late");
				expect((await s.removeIf(key("a"), { version }, late)).kind).toBe("late");
				expect((await s.batch([], [{ key: key("b"), remove: true }], late)).kind).toBe("late");
				expect((await s.batch([], [], late)).kind).toBe("late");
				const mutated = await mutate(
					s,
					key("a"),
					() => ({ kind: "write", value: 3, expiry: { kind: "keep" } }),
					late,
				);
				expect(mutated.kind).toBe("late");
				const removing = await mutate(s, key("a"), () => ({ kind: "remove" }), late);
				expect(removing.kind).toBe("late");
				expect((await s.get(key("a"))).entry?.value).toBe(1);
			});

			it("refuses a take past its deadline and leaves the entry", async () => {
				const s = await harness.open();
				const k = fresh()("a");
				await overwrite(s, k, 1, never);
				const { now } = await s.get(k);
				expect((await s.take(k, { deadline: now - 1 })).kind).toBe("late");
				expect((await s.get(k)).entry?.value).toBe(1);
			});

			it("honours count deadlines and binds take and count marks to their key and window", async () => {
				const s = await harness.open();
				const key = fresh();
				const { now } = await s.get(key("x"));
				expect(
					(await s.count(key("hits"), { ms: 10_000, limit: 5 }, { deadline: now - 1 })).kind,
				).toBe("late");
				const mark = { deadline: now + 60_000, idempotency: "m" };
				await s.count(key("hits"), { ms: 10_000, limit: 5 }, mark);
				expect((await s.count(key("hits"), { ms: 20_000, limit: 5 }, mark)).kind).toBe("reused");
				await overwrite(s, key("a"), 1, never);
				await overwrite(s, key("b"), 1, never);
				await s.take(key("a"), { ...mark, idempotency: "t" });
				expect((await s.take(key("b"), { ...mark, idempotency: "t" })).kind).toBe("reused");
			});

			it("answers a resend with the first answer, refuses a reused mark and forgets marks in time", async () => {
				const s = await harness.open();
				const key = fresh();
				const { now } = await s.get(key("a"));
				const options = { ...never, deadline: now + 60_000, idempotency: "once" };
				const first = await s.putIfAbsent(key("a"), 1, options);
				expect(await s.putIfAbsent(key("a"), 1, options)).toEqual(first);
				expect((await s.putIfAbsent(key("b"), 1, options)).kind).toBe("reused");
				expect((await s.get(key("b"))).entry).toBeNull();
				const { expiry: _, ...limits } = options;
				expect((await s.removeIf(key("a"), { value: 1 }, limits)).kind).toBe("reused");
				// A networked store needs room for one round trip before the deadline.
				const short = { ...never, deadline: now + 1_000, idempotency: "short" };
				expect((await s.putIfAbsent(key("c"), 1, short)).kind).toBe("written");
				// Forgotten 1 second after the deadline, checked with 400 ms to spare.
				await sleep(2_400);
				const { now: later } = await s.get(key("c"));
				const resend = await s.putIfAbsent(key("c"), 1, { ...short, deadline: later + 60_000 });
				expect(resend.kind).toBe("exists");
			});

			it("binds a mark to the request's values and partition, for every write that takes one", async () => {
				const s = await harness.open();
				const key = fresh();
				const other = fresh();
				const { now } = await s.get(key("x"));
				const mark = (idempotency: string) => ({ deadline: now + 60_000, idempotency });
				expect(
					(await s.putIfAbsent(key("a"), { x: 1, y: 2 }, { ...never, ...mark("m1") })).kind,
				).toBe("written");
				expect(
					(await s.putIfAbsent(key("a"), { y: 2, x: 1 }, { ...never, ...mark("m1") })).kind,
				).toBe("written");
				expect(
					(await s.putIfAbsent(key("a"), { x: 1, y: 3 }, { ...never, ...mark("m1") })).kind,
				).toBe("reused");
				expect((await s.putIfAbsent(other("a"), 1, { ...never, ...mark("m1") })).kind).toBe(
					"written",
				);
				const version = versionOf(await overwrite(s, key("v"), 1, never));
				const replaced = await s.replaceIf(key("v"), version, 2, { ...never, ...mark("m2") });
				expect(await s.replaceIf(key("v"), version, 2, { ...never, ...mark("m2") })).toEqual(
					replaced,
				);
				expect((await s.replaceIf(key("v"), version, 3, { ...never, ...mark("m2") })).kind).toBe(
					"reused",
				);
				const batch = [{ key: key("b"), put: 1, expiry: { kind: "never" } }] as const;
				const committed = await s.batch([{ key: key("b"), absent: true }], batch, mark("m3"));
				expect(await s.batch([{ key: key("b"), absent: true }], batch, mark("m3"))).toEqual(
					committed,
				);
				expect((await s.batch([], batch, mark("m3"))).kind).toBe("reused");
				const removed = await s.removeIf(key("b"), { value: 1 }, mark("m4"));
				expect(await s.removeIf(key("b"), { value: 1 }, mark("m4"))).toEqual(removed);
				expect((await s.removeIf(key("b"), { value: 2 }, mark("m4"))).kind).toBe("reused");
			});

			it("binds a mark to the operation, not only to its keys and values", async () => {
				const s = await harness.open();
				const key = fresh();
				const { now } = await s.get(key("x"));
				const mark = { ...never, deadline: now + 60_000, idempotency: "op" };
				expect((await s.putIfAbsent(key("a"), 1, mark)).kind).toBe("written");
				expect((await s.replaceIf(key("a"), "any", 1, mark)).kind).toBe("reused");
			});

			it("binds a batch mark to the kind of each condition, not only to its text", async () => {
				const s = await harness.open();
				const key = fresh();
				const { now } = await s.get(key("x"));
				const mark = { deadline: now + 60_000, idempotency: "kinds" };
				const writes = [{ key: key("b"), put: 1, expiry: { kind: "never" } }] as const;
				expect((await s.batch([{ key: key("b"), absent: true }], writes, mark)).kind).toBe(
					"committed",
				);
				expect((await s.batch([{ key: key("b"), version: "absent" }], writes, mark)).kind).toBe(
					"reused",
				);
			});

			it("answers a resend inside the skew after the deadline with the first answer", async () => {
				const s = await harness.open();
				const k = fresh()("a");
				const { now } = await s.get(k);
				const options = { ...never, deadline: now + 100, idempotency: "m" };
				const first = await s.putIfAbsent(k, 1, options);
				await sleep(300);
				expect(await s.putIfAbsent(k, 1, options)).toEqual(first);
			});

			it("lets a taker or counter learn its first answer by resending its mark", async () => {
				const s = await harness.open();
				const key = fresh();
				await overwrite(s, key("a"), "only", never);
				const { now } = await s.get(key("a"));
				const mark = { deadline: now + 60_000, idempotency: "t1" };
				const taken = await s.take(key("a"), mark);
				expect(taken.kind).toBe("taken");
				expect(await s.take(key("a"), mark)).toEqual(taken);
				expect((await s.take(key("a"))).kind).toBe("missing");
				const counted = await s.count(key("hits"), { ms: 10_000, limit: 5 }, { idempotency: "c1" });
				expect(await s.count(key("hits"), { ms: 10_000, limit: 5 }, { idempotency: "c1" })).toEqual(
					counted,
				);
				expect(await s.count(key("hits"), { ms: 10_000, limit: 5 })).toMatchObject({
					kind: "counted",
					count: 2,
				});
			});

			it("remembers a refusing first answer for its mark even after the state changes", async () => {
				const s = await harness.open();
				const k = fresh()("a");
				await overwrite(s, k, 1, never);
				const { now } = await s.get(k);
				const mark = { ...never, deadline: now + 60_000, idempotency: "neg" };
				const first = await s.putIfAbsent(k, 2, mark);
				expect(first.kind).toBe("exists");
				await s.removeIf(k, { value: 1 });
				expect(await s.putIfAbsent(k, 2, mark)).toEqual(first);
				expect((await s.get(k)).entry).toBeNull();
			});

			it.runIf(harness.loseNextReply !== undefined)(
				"answers unavailable when a reply is lost, and the first answer to a resend of the same mark",
				async () => {
					const s = await harness.open();
					const key = fresh();
					await overwrite(s, key("a"), "only", never);
					const { now } = await s.get(key("a"));
					const mark = { deadline: now + 60_000, idempotency: "lost" };
					await harness.loseNextReply?.(s);
					await expect(s.take(key("a"), mark)).rejects.toMatchObject({ name: "Unavailable" });
					const resent = await eventually(() => s.take(key("a"), mark), 50);
					expect(resent).toMatchObject({ kind: "taken", entry: { value: "only" } });
					await harness.loseNextReply?.(s);
					await expect(
						s.count(key("hits"), { ms: 10_000, limit: 5 }, { idempotency: "c" }),
					).rejects.toMatchObject({
						name: "Unavailable",
					});
					const counted = await eventually(
						() => s.count(key("hits"), { ms: 10_000, limit: 5 }, { idempotency: "c" }),
						50,
					);
					expect(counted).toMatchObject({ kind: "counted", count: 1 });
				},
				30_000,
			);
		});

		describe("concurrent connections", () => {
			it("writes several keys of a partition as one, under concurrent connections", async () => {
				const [s, t] = await both();
				const key = fresh();
				const writers = race(30, [s, t], (store, i) =>
					store.batch(
						[],
						[
							{ key: key("a"), put: i, expiry: { kind: "never" } },
							{ key: key("b"), put: i, expiry: { kind: "never" } },
						],
					),
				);
				await writers;
				expect((await t.get(key("a"))).entry?.value).toEqual((await s.get(key("b"))).entry?.value);
			});

			it("takes an entry exactly once among racing takers on two connections", async () => {
				const [s, t] = await both();
				const k = fresh()("a");
				await overwrite(s, k, "only", never);
				const results = await race(20, [s, t], (store) => store.take(k));
				expect(results.filter((r) => r.kind === "taken")).toHaveLength(1);
			});

			it("lets exactly one racing writer in when writing if absent or on a version", async () => {
				const [s, t] = await both();
				const key = fresh();
				const absent = await race(20, [s, t], (store, i) => store.putIfAbsent(key("a"), i, never));
				expect(absent.filter((r) => r.kind === "written")).toHaveLength(1);
				const version = versionOf(await overwrite(s, key("b"), 0, never));
				const replaced = await race(20, [s, t], (store, i) =>
					store.replaceIf(key("b"), version, i, never),
				);
				expect(replaced.filter((r) => r.kind === "written")).toHaveLength(1);
			});

			it("loses no increment when mutating concurrently from two connections", async () => {
				const [s, t] = await both();
				const k = fresh()("counter");
				const increments = await race(25, [s, t], (store) =>
					mutate(
						store,
						k,
						(entry) => ({
							kind: "write",
							value: ((entry?.value as number) ?? 0) + 1,
							expiry: { kind: "keep" },
						}),
						{ attempts: 200 },
					),
				);
				expect(increments.every((r) => r.kind === "done")).toBe(true);
				expect((await s.get(k)).entry?.value).toBe(25);
			});

			it("re-runs the decision on the newer entry instead of resending a stale write", async () => {
				const s = await harness.open();
				const k = fresh()("doc");
				await overwrite(s, k, { a: 0, b: 0 }, never);
				let runs = 0;
				let rival: Promise<unknown> = Promise.resolve();
				const result = await mutate(s, k, (entry) => {
					runs += 1;
					const doc = entry?.value as { a: number; b: number };
					// Another client rewrites b after the first read and before the write.
					if (runs === 1 && entry) rival = s.replaceIf(k, entry.version, { ...doc, b: 1 }, never);
					return { kind: "write", value: { ...doc, a: 1 }, expiry: { kind: "keep" } };
				});
				await rival;
				expect(result.kind).toBe("done");
				expect(runs).toBeGreaterThan(1);
				expect((await s.get(k)).entry?.value).toEqual({ a: 1, b: 1 });
			});
		});

		describe("batches across partitions and spaces", () => {
			/** The store's batch across partitions, or a skip where it offers none. */
			const across = (s: Store, skip: () => void) => {
				const batchAcross = s.batchAcross?.bind(s);
				if (!batchAcross) {
					skip();
					throw new Error("skipped");
				}
				return batchAcross;
			};

			it("commits across partitions and spaces only when every condition holds, answering in the input's order", async (ctx) => {
				const s = await harness.open();
				const batchAcross = across(s, () => ctx.skip());
				const [a, b, c] = [fresh()("a"), fresh()("b"), fresh(twin)("c")];
				const version = versionOf(await overwrite(s, a, 1, never));
				const lost = await batchAcross(
					[
						{ key: a, version },
						{ key: c, absent: true },
						{ key: a, version: `${version}x` },
					],
					[{ key: b, put: 2, expiry: { kind: "never" } }],
				);
				expect(lost).toEqual({ kind: "conflict", index: 2 });
				expect((await s.get(b)).entry).toBeNull();
				const won = await batchAcross(
					[
						{ key: a, version },
						{ key: c, absent: true },
					],
					[
						{ key: c, put: 3, expiry: { kind: "never" } },
						{ key: a, remove: true },
						{ key: b, put: 2, expiry: { kind: "never" } },
					],
				);
				expect(won.kind === "committed" && won.versions.length).toBe(3);
				if (won.kind !== "committed") throw new Error(won.kind);
				expect(won.versions[1]).toBeNull();
				expect((await s.get(c)).entry?.version).toBe(won.versions[0]);
				expect((await s.get(b)).entry?.version).toBe(won.versions[2]);
				expect((await s.get(a)).entry).toBeNull();
			});

			it("holds a key it only reads, and answers an empty request by its deadline alone", async (ctx) => {
				const s = await harness.open();
				const batchAcross = across(s, () => ctx.skip());
				const [watched, written] = [fresh()("w"), fresh()("x")];
				const version = versionOf(await overwrite(s, watched, 1, never));
				await overwrite(s, watched, 2, never);
				const stale = await batchAcross(
					[{ key: watched, version }],
					[{ key: written, put: 1, expiry: { kind: "never" } }],
				);
				expect(stale).toEqual({ kind: "conflict", index: 0 });
				expect((await s.get(written)).entry).toBeNull();
				const { now } = await s.get(watched);
				expect(await batchAcross([], [], { deadline: now + 60_000, idempotency: "empty" })).toEqual(
					{
						kind: "committed",
						versions: [],
					},
				);
				expect((await batchAcross([], [], { deadline: now - 1 })).kind).toBe("late");
			});

			it("refuses spaces of other guarantees, a key written twice and an undeclared space", async (ctx) => {
				const s = await harness.open();
				const batchAcross = across(s, () => ctx.skip());
				const put = (key: Key) => ({ key, put: 1, expiry: { kind: "never" } }) as const;
				await expect(
					batchAcross([], [put(fresh()("a")), put(fresh(replicated)("b"))]),
				).rejects.toThrow();
				const k = fresh()("a");
				await expect(batchAcross([], [put(k), put({ ...k })])).rejects.toThrow();
				const undeclared = { name: "nowhere", guarantees: [] } as Space;
				await expect(
					batchAcross([], [put(fresh()("a")), put(fresh(undeclared)("b"))]),
				).rejects.toThrow();
			});

			it("binds its mark to the request, met in every partition it touches, its order included", async (ctx) => {
				const s = await harness.open();
				const batchAcross = across(s, () => ctx.skip());
				const [a, b, c, d] = [fresh()("a"), fresh()("b"), fresh(twin)("c"), fresh()("d")];
				const { now } = await s.get(a);
				const options = { deadline: now + 60_000, idempotency: "across" };
				const put = (key: Key, value: number) =>
					({ key, put: value, expiry: { kind: "never" } }) as const;
				const first = await batchAcross(
					[{ key: c, absent: true }],
					[put(a, 1), put(b, 1)],
					options,
				);
				expect(first.kind).toBe("committed");
				await overwrite(s, a, 9, never);
				// The same request sent again gets its first answer, though the state moved since.
				expect(
					await batchAcross([{ key: c, absent: true }], [put(a, 1), put(b, 1)], options),
				).toEqual(first);
				// Another request meeting the mark in its last partition only, or in a partition it only reads.
				expect((await batchAcross([], [put(d, 1), put(b, 2)], options)).kind).toBe("reused");
				expect((await batchAcross([{ key: c, absent: true }], [put(d, 1)], options)).kind).toBe(
					"reused",
				);
				// The same keys in another order are another request.
				expect(
					(await batchAcross([{ key: c, absent: true }], [put(b, 1), put(a, 1)], options)).kind,
				).toBe("reused");
				expect((await s.get(d)).entry).toBeNull();
				expect(
					await batchAcross([{ key: c, absent: true }], [put(a, 1), put(b, 1)], options),
				).toEqual(first);
			});

			it("remembers a conflict for its mark though its condition holds later, and keeps no late answer", async (ctx) => {
				const s = await harness.open();
				const batchAcross = across(s, () => ctx.skip());
				const [a, b] = [fresh()("a"), fresh(twin)("b")];
				await overwrite(s, a, 1, never);
				const { now } = await s.get(a);
				const put = (key: Key) => ({ key, put: 2, expiry: { kind: "never" } }) as const;
				const refused = { deadline: now + 60_000, idempotency: "refused" };
				const conflict = await batchAcross([{ key: a, absent: true }], [put(b)], refused);
				expect(conflict).toEqual({ kind: "conflict", index: 0 });
				// The condition holds now: only the mark answers the resend with its conflict.
				expect((await s.removeIf(a, { value: 1 })).kind).toBe("removed");
				expect(await batchAcross([{ key: a, absent: true }], [put(b)], refused)).toEqual(conflict);
				expect((await s.get(b)).entry).toBeNull();
				// The same request, late and then in time: a kept late answer would answer it late again.
				expect(
					(await batchAcross([], [put(b)], { deadline: now - 1, idempotency: "late" })).kind,
				).toBe("late");
				expect(
					(await batchAcross([], [put(b)], { deadline: now + 60_000, idempotency: "late" })).kind,
				).toBe("committed");
			});

			it("finds its mark in a later partition past the deadline, and keeps it to one end in every partition", async (ctx) => {
				const s = await harness.open();
				const batchAcross = across(s, () => ctx.skip());
				const [c, d, e] = [fresh()("c"), fresh(twin)("d"), fresh()("e")];
				const put = (key: Key) => ({ key, put: 2, expiry: { kind: "never" } }) as const;
				const { now } = await s.get(c);
				// A networked store needs room for one round trip before the deadline.
				const short = { deadline: now + 1_000, idempotency: "short" };
				expect((await batchAcross([], [put(c), put(d)], short)).kind).toBe("committed");
				// Past the deadline, before the mark's end a second after it, with 600 ms to spare.
				await sleep(1_400);
				// Its first partition free of the mark and its last holding it: reused, never late.
				expect((await batchAcross([], [put(e), put(d)], short)).kind).toBe("reused");
				expect((await batchAcross([], [put(c)], short)).kind).toBe("reused");
				expect((await s.get(e)).entry).toBeNull();
				// Past the end, with 400 ms to spare: forgotten in both partitions alike.
				await sleep(1_000);
				const { now: later } = await s.get(c);
				const again = { deadline: later + 60_000, idempotency: "short" };
				expect((await batchAcross([], [put(c)], again)).kind).toBe("committed");
				expect((await batchAcross([], [put(d)], again)).kind).toBe("committed");
			});

			it("never repeats a version of a key, whichever partition's batch writes it", async (ctx) => {
				const s = await harness.open();
				const batchAcross = across(s, () => ctx.skip());
				const [key, other] = [fresh(), fresh(twin)];
				const seen = new Map<string, Set<string>>();
				for (let i = 0; i < 6; i++) {
					const written = await batchAcross(
						[],
						[
							{ key: key("a"), put: i, expiry: { kind: "never" } },
							{ key: other("b"), put: i, expiry: { kind: "never" } },
						],
					);
					if (written.kind !== "committed") throw new Error(written.kind);
					const one = await s.batch([], [{ key: key("a"), put: -i, expiry: { kind: "never" } }]);
					if (one.kind !== "committed") throw new Error(one.kind);
					for (const [name, version] of [
						["a", written.versions[0]],
						["b", written.versions[1]],
						["a", one.versions[0]],
					] as const) {
						const versions = seen.get(name) ?? new Set();
						expect(versions.has(String(version)), `${name} ${version}`).toBe(false);
						versions.add(String(version));
						seen.set(name, versions);
					}
				}
			});

			it("writes keys of several partitions as one, under concurrent connections", async (ctx) => {
				const [s, t] = await both();
				across(s, () => ctx.skip());
				const [a, b] = [fresh()("a"), fresh(twin)("b")];
				await race(30, [s, t], (store, i) =>
					across(store, () => ctx.skip())(
						[],
						[
							{ key: a, put: i, expiry: { kind: "never" } },
							{ key: b, put: i, expiry: { kind: "never" } },
						],
					),
				);
				expect((await t.get(a)).entry?.value).toEqual((await s.get(b)).entry?.value);
			});
		});

		describe("counting", () => {
			it("counts in a fixed window that hits do not extend, refusing at the limit under races", async () => {
				const [s, t] = await both();
				const k = fresh()("hits");
				const results = await race(30, [s, t], (store) =>
					store.count(k, { ms: 10_000, limit: 10 }),
				);
				expect(results.filter((r) => r.kind === "counted")).toHaveLength(10);
				const resets = new Set(results.map((r) => ("resetAt" in r ? r.resetAt : -1)));
				await sleep(30);
				const later = await s.count(k, { ms: 10_000, limit: 10 });
				expect(later.kind).toBe("limited");
				expect(resets.size).toBe(1);
				expect("resetAt" in later && resets.has(later.resetAt)).toBe(true);
			});

			it("starts a new window once the old one has passed", async () => {
				const s = await harness.open();
				const k = fresh()("hits");
				expect((await s.count(k, { ms: 150, limit: 1 })).kind).toBe("counted");
				expect((await s.count(k, { ms: 150, limit: 1 })).kind).toBe("limited");
				await sleep(400);
				expect(await s.count(k, { ms: 150, limit: 1 })).toMatchObject({
					kind: "counted",
					count: 1,
				});
			});
		});

		describe("scanning a space", () => {
			const walk = async (s: Store, target: Space, between?: () => Promise<void>) => {
				const seen = new Map<string, number>();
				let cursor: string | undefined;
				do {
					const page = await s.scan(target, cursor);
					for (const k of page.keys) {
						expect(k.space.name).toBe(target.name);
						const id = `${k.partition}/${k.name}`;
						seen.set(id, (seen.get(id) ?? 0) + 1);
					}
					cursor = page.cursor;
					await between?.();
				} while (cursor !== undefined);
				return seen;
			};

			it("lists each live value's key in the space, over pages, and no counter, set or other space", async () => {
				const s = await harness.open();
				const live = Array.from({ length: 250 }, (_, i) => fresh(space, `q${i % 7}`)(`k${i}`));
				for (const k of live) await overwrite(s, k, 1, never);
				const { now } = await s.get(fresh()("probe"));
				const ends = now + 30;
				await overwrite(s, fresh()("gone"), 1, { expiry: { kind: "at", at: ends } });
				while ((await s.now()) <= ends) await sleep(5);
				await overwrite(s, fresh(replicated)("elsewhere"), 1, never);
				await s.count(fresh()("counted"), { ms: 60_000, limit: 5 });
				const seen = await walk(s, space);
				expect([...seen.keys()].sort()).toEqual(live.map((k) => `${k.partition}/${k.name}`).sort());
				expect([...(await walk(s, replicated)).keys()]).toHaveLength(1);
				expect([...(await walk(await harness.open(), space)).keys()]).toEqual([]);
			});

			it("lists every key that lives through the walk, whatever is written or removed meanwhile", async () => {
				const s = await harness.open();
				const kept = Array.from({ length: 120 }, (_, i) => fresh(space, "w")(`kept${i}`));
				const dropped = Array.from({ length: 120 }, (_, i) => fresh(space, "w")(`dropped${i}`));
				for (const k of [...kept, ...dropped]) await overwrite(s, k, 1, never);
				let n = 0;
				const seen = await walk(s, space, async () => {
					const k = dropped[n];
					if (k) await s.removeIf(k, { value: 1 });
					await overwrite(s, fresh(space, "w")(`added${n++}`), 1, never);
				});
				for (const k of kept) expect(seen.get(`w/${k.name}`), k.name).toBeGreaterThanOrEqual(1);
			});

			it("refuses a space that is not declared", async () => {
				const s = await harness.open();
				await expect(s.scan({ name: "undeclared", guarantees: [] })).rejects.toThrow();
			});
		});

		describe("input checks", () => {
			it("refuses times, durations and limits that are not whole numbers in range", async () => {
				const s = await harness.open();
				const k = fresh()("a");
				await expect(overwrite(s, k, 1, { expiry: { kind: "after", ms: 1.5 } })).rejects.toThrow(
					TypeError,
				);
				await expect(overwrite(s, k, 1, { expiry: { kind: "at", at: -1 } })).rejects.toThrow(
					TypeError,
				);
				await expect(s.putIfAbsent(k, 1, { ...never, deadline: 0.5 })).rejects.toThrow(TypeError);
				await expect(
					s.batch([], [{ key: k, put: 1, expiry: { kind: "after", ms: Number.NaN } }]),
				).rejects.toThrow(TypeError);
				await expect(s.count(k, { ms: 10.5, limit: 1 })).rejects.toThrow(TypeError);
				expect((await s.get(k)).entry).toBeNull();
			});

			it("accepts only plain JSON values and applies nothing of a batch with one bad value", async () => {
				const s = await harness.open();
				const key = fresh();
				for (const bad of [
					undefined,
					Number.NaN,
					Number.POSITIVE_INFINITY,
					new Date(0),
					new Map(),
					() => 1,
				]) {
					await expect(overwrite(s, key("a"), bad as never, never)).rejects.toThrow(TypeError);
				}
				await expect(
					s.batch(
						[],
						[
							{ key: key("b"), put: 1, expiry: { kind: "never" } },
							{ key: key("c"), put: { at: new Date(0) } as never, expiry: { kind: "never" } },
						],
					),
				).rejects.toThrow(TypeError);
				for (const name of ["a", "b", "c"]) expect((await s.get(key(name))).entry).toBeNull();
				await expect(
					overwrite(
						s,
						{ space: { name: "undeclared", guarantees: [] }, partition: "p", name: "a" },
						1,
						never,
					),
				).rejects.toThrow(TypeError);
			});

			it("refuses malformed inputs to every operation", async () => {
				const s = await harness.open();
				const k = fresh()("a");
				await expect(s.replaceIf(k, "", 1, never)).rejects.toThrow(TypeError);
				await expect(s.removeIf(k, { version: 1 as never })).rejects.toThrow(TypeError);
				await expect(s.count(k, { ms: 1000, limit: -1 })).rejects.toThrow(TypeError);
				await expect(s.take(k, { deadline: -1 })).rejects.toThrow(TypeError);
			});

			it("refuses options with unknown or hidden properties", async () => {
				const s = await harness.open();
				const k = fresh()("a");
				await expect(overwrite(s, k, 1, { ...never, deadlin: 1 } as never)).rejects.toThrow(
					TypeError,
				);
				const hidden = Object.defineProperty({ ...never }, "deadline", {
					value: 0,
					enumerable: false,
				});
				await expect(overwrite(s, k, 1, hidden)).rejects.toThrow(TypeError);
				await expect(s.count(k, { ms: 1000, limit: 1, extra: 1 } as never)).rejects.toThrow(
					TypeError,
				);
			});

			it("takes only well-formed strings and keeps non-ASCII keys and members apart, in code point order", async () => {
				const s = await harness.open();
				const key = fresh();
				const lone = "\uD800";
				await expect(overwrite(s, key(lone), 1, never)).rejects.toThrow(TypeError);
				await expect(overwrite(s, key("a"), lone, never)).rejects.toThrow(TypeError);
				await expect(overwrite(s, key("a"), { [lone]: 1 }, never)).rejects.toThrow(TypeError);
				await expect(s.putIfAbsent(key("a"), 1, { ...never, idempotency: lone })).rejects.toThrow(
					TypeError,
				);
				await overwrite(s, key("é😀"), "é😀", never);
				expect((await s.get(key("é😀"))).entry?.value).toBe("é😀");
				expect((await s.get(key("e😀"))).entry).toBeNull();
			});

			it("refuses values and arguments that are not plain data read once", async () => {
				const s = await harness.open();
				const key = fresh();
				class Point {
					x = 1;
				}
				const extra = Object.assign([1], { note: "x" });
				const proto = JSON.parse('{"__proto__": 1}');
				const getter = Object.defineProperty({}, "x", { get: () => 1, enumerable: true });
				for (const bad of [new Point(), extra, proto, getter]) {
					await expect(overwrite(s, key("a"), bad as never, never)).rejects.toThrow(TypeError);
				}
				const sneaky = Object.defineProperty({ space, partition: "p" }, "name", {
					get: () => "a",
					enumerable: true,
				});
				await expect(s.get(sneaky as Key)).rejects.toThrow(TypeError);
				await overwrite(s, key("z"), -0, never);
				expect(Object.is((await s.get(key("z"))).entry?.value, 0)).toBe(true);
				await expect(
					s.batch(
						[],
						[
							{ key: key("b"), put: 1, expiry: { kind: "never" } },
							{ key: key("b"), put: 2, expiry: { kind: "never" } },
						],
					),
				).rejects.toThrow(TypeError);
			});

			it("refuses each malformed part of a key, an option, a value, a condition and a member", async () => {
				const s = await harness.open();
				const k = fresh()("a");
				class Items extends Array<number> {}
				const trailingHole = [1];
				trailingHole.length = 2;
				const holeAndExtra = Object.assign([1], { x: 1 });
				holeAndExtra.length = 2;
				let deep: unknown = 1;
				for (let i = 0; i < 100; i++) deep = [deep];
				const hiddenDeadline = Object.defineProperty({ ...never }, "deadline", {
					get: () => 1,
					enumerable: true,
				});
				const refused: Record<string, () => Promise<unknown>> = {
					"long key name": () => s.get(fresh()("x".repeat(513))),
					"empty partition": () => s.get({ ...k, partition: "" }),
					"time past the last date": () =>
						overwrite(s, k, 1, { expiry: { kind: "at", at: 8.65e15 } }),
					"limit past its range": () => s.count(k, { ms: 1000, limit: 1_000_000_001 }),
					"zero duration": () => overwrite(s, k, 1, { expiry: { kind: "after", ms: 0 } }),
					"unknown expiry": () => overwrite(s, k, 1, { expiry: { kind: "forever" } as never }),
					"option with a getter": () => overwrite(s, k, 1, hiddenDeadline),
					"batch option": () => s.batch([], [], { deadline: 0.5 }),
					"symbol key in a value": () => overwrite(s, k, { [Symbol("x")]: 1 } as never, never),
					"array subclass": () => overwrite(s, k, Items.from([1]) as never, never),
					"array with a trailing hole": () => overwrite(s, k, trailingHole, never),
					"array with a hole and a property": () => overwrite(s, k, holeAndExtra, never),
					"array with a symbol": () =>
						overwrite(s, k, Object.assign([1], { [Symbol("x")]: 1 }), never),
					"value nested too deeply": () => overwrite(s, k, deep as never, never),
					"value expected by a removal": () => s.removeIf(k, { value: new Date(0) as never }),
					"empty condition version": () => s.batch([{ key: k, version: "" }], []),
					"condition with neither": () => s.batch([{ key: k } as never], []),
				};
				for (const [label, run] of Object.entries(refused)) {
					await expect(run(), label).rejects.toThrow(TypeError);
				}
				expect((await s.get(k)).entry).toBeNull();
			});
		});

		describe("replication faults", () => {
			it.runIf(harness.stopReplicas !== undefined)(
				"answers unavailable when a replicated space's write is not acknowledged by the replicas",
				async () => {
					const s = await harness.open();
					const partition = `p${++n}`;
					const at = fresh(replicated, partition);
					const disguised = fresh({ ...replicated, guarantees: [] }, partition);
					await overwrite(s, at("a"), 1, never);
					await overwrite(s, at("b"), 1, never);
					const version = versionOf(await overwrite(s, at("r"), 1, never));
					const vVersion = versionOf(await overwrite(s, at("v"), 1, never));
					await overwrite(s, at("w"), 1, never);
					const undo = await harness.stopReplicas?.();
					try {
						expect((await s.putIfAbsent(fresh()("plain"), 1, never)).kind).toBe("written");
						const unconfirmed: Record<string, () => Promise<unknown>> = {
							putIfAbsent: () => s.putIfAbsent(at("new"), 2, never),
							replaceIf: () => s.replaceIf(at("v"), vVersion, 2, never),
							"removeIf by value": () => s.removeIf(at("w"), { value: 1 }),
							"putIfAbsent with a key that hides the guarantee": () =>
								s.putIfAbsent(disguised("c"), 2, never),
							take: () => s.take(at("b")),
							"removeIf by version": () => s.removeIf(at("r"), { version }),
							batch: () => s.batch([], [{ key: at("d"), put: 1, expiry: { kind: "never" } }]),
							count: () => s.count(at("hits"), { ms: 10_000, limit: 5 }),
						};
						for (const [label, run] of Object.entries(unconfirmed)) {
							await expect(run(), label).rejects.toMatchObject({ name: "Unavailable" });
						}
					} finally {
						await undo?.();
					}
				},
				30_000,
			);

			it.runIf(harness.stopReplicas !== undefined)(
				"does not confirm a resent mark on a new connection while the replicas lack the write",
				async () => {
					const s = await harness.open();
					const t = await harness.peer(s);
					const k = fresh(replicated)("a");
					await overwrite(s, k, "code", never);
					const { now } = await s.get(k);
					const mark = { deadline: now + 60_000, idempotency: "once" };
					const undo = await harness.stopReplicas?.();
					try {
						await expect(s.take(k, mark)).rejects.toMatchObject({ name: "Unavailable" });
						await expect(t.take(k, mark)).rejects.toMatchObject({ name: "Unavailable" });
					} finally {
						await undo?.();
					}
					expect(await t.take(k, mark)).toMatchObject({ kind: "taken", entry: { value: "code" } });
				},
				30_000,
			);

			it.runIf(harness.stopReplicas !== undefined)(
				"confirms reads and refusing answers where the space asks for it, and only there",
				async () => {
					const s = await harness.open();
					const partition = `p${++n}`;
					const at = fresh(confirmed, partition);
					const plain = fresh(replicated, partition);
					const version = versionOf(await overwrite(s, at("a"), 1, never));
					await overwrite(s, plain("a"), 1, never);
					const { now } = await s.get(at("a"));
					await s.count(at("hits"), { ms: 60_000, limit: 1 });
					const undo = await harness.stopReplicas?.();
					try {
						const unconfirmed: Record<string, () => Promise<unknown>> = {
							get: () => s.get(at("a")),
							"putIfAbsent, exists": () => s.putIfAbsent(at("a"), 2, never),
							"replaceIf, conflict": () => s.replaceIf(at("a"), `${version}x`, 2, never),
							"take, missing": () => s.take(at("none")),
							"removeIf, missing": () => s.removeIf(at("none"), { value: 1 }),
							"count, limited": () => s.count(at("hits"), { ms: 60_000, limit: 1 }),
							"batch, conflict": () => s.batch([{ key: at("a"), absent: true }], []),
							"removeIf, conflict": () => s.removeIf(at("a"), { value: 99 }),
							"replaceIf, missing": () => s.replaceIf(at("none"), version, 2, never),
							"putIfAbsent, late": () =>
								s.putIfAbsent(at("late"), 1, { ...never, deadline: now - 1 }),
						};
						for (const [label, run] of Object.entries(unconfirmed)) {
							await expect(run(), label).rejects.toMatchObject({ name: "Unavailable" });
						}
						expect((await s.get(plain("a"))).entry?.value).toBe(1);
					} finally {
						await undo?.();
					}
					expect((await s.get(at("a"))).entry?.value).toBe(1);
				},
				30_000,
			);

			it.runIf(harness.stopReplicas !== undefined && harness.failover !== undefined)(
				"answers a confirmed read of an unconfirmed write only once it is confirmed",
				async () => {
					const s = await harness.open();
					const k = fresh(confirmed)("a");
					const undo = await harness.stopReplicas?.();
					let resumed = false;
					let early: unknown;
					let reading: Promise<unknown> = Promise.resolve();
					try {
						await expect(overwrite(s, k, 1, never)).rejects.toMatchObject({ name: "Unavailable" });
						reading = s.get(k).then(
							(read) => {
								if (!resumed) early = read.entry?.value ?? null;
							},
							() => undefined,
						);
						await sleep(200);
					} finally {
						resumed = true;
						await undo?.();
					}
					await reading;
					expect(early).not.toBe(1);
					const answered = await eventually(() => s.get(k), 300);
					if (!answered) throw new Error("no confirmed read after the replicas resumed");
					const promoted = await harness.failover?.();
					try {
						// Unavailable keeps nothing from the caller; an answer must agree with the earlier one.
						const after = await eventually(() => s.get(k), 30);
						if (after) expect(after.entry?.value ?? null).toBe(answered.entry?.value ?? null);
					} finally {
						await promoted?.();
					}
				},
				120_000,
			);

			it.runIf(harness.stopReplicas !== undefined)(
				"keeps serving other commands while a replicated write waits for its confirmation",
				async () => {
					const s = await harness.open();
					const k = fresh(replicated)("a");
					const other = fresh()("b");
					await overwrite(s, other, 1, never);
					const undo = await harness.stopReplicas?.();
					try {
						const waiting = overwrite(s, k, 1, never).then(
							() => "written",
							() => "unavailable",
						);
						await sleep(50);
						const started = Date.now();
						expect((await s.get(other)).entry?.value).toBe(1);
						expect(Date.now() - started).toBeLessThan(500);
						expect(await waiting).toBe("unavailable");
					} finally {
						await undo?.();
					}
				},
				30_000,
			);

			it.runIf(harness.failover !== undefined && harness.stopReplicas !== undefined)(
				"confirms, with a later write, state written before it in another partition",
				async () => {
					const s = await harness.open();
					const earlier = fresh()("earlier");
					const later = fresh(replicated)("later");
					await overwrite(s, earlier, "kept", never);
					expect((await s.putIfAbsent(later, 1, never)).kind).toBe("written");
					await harness.stopReplicas?.();
					const undo = await harness.failover?.();
					try {
						const read = await eventually(() => s.get(earlier), 100);
						expect(read?.entry?.value).toBe("kept");
					} finally {
						await undo?.();
					}
				},
				120_000,
			);
		});
	});
}

export type StoreSettings = z.input<typeof section>;

/** The store part of a test's configuration: the memory store, accepted though it forgets on restart. */
export function storeConfig(settings: Partial<StoreSettings> = {}) {
	return { store: { "accept-volatile": true, ...settings } };
}
