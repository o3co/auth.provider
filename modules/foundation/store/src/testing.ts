import { describe, expect, it } from "vitest";
import type { z } from "zod";
import {
	getFollowing,
	type Key,
	mutate,
	type Space,
	type Store,
	type Version,
} from "./contract.ts";
import type { section } from "./section.ts";

export { type SimulatedStore, simulatedStore } from "./simulated.ts";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** The spaces the contract tests use; a harness declares them when it opens a store. */
export const contractSpaces: readonly Space[] = Object.freeze([
	{ name: "contract", guarantees: [] },
	{ name: "contract-replicated", guarantees: ["replicated"] },
	{ name: "contract-confirmed", guarantees: ["replicated", "confirmed-reads"] },
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
	const [space, replicated, confirmed] = contractSpaces as [Space, Space, Space];
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
				const version = versionOf(await s.put(k, { x: [1, "y"] }, never));
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
				const version = versionOf(await s.put(k, "one", never));
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
				const version = versionOf(await s.put(key("a"), 1, never));
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
				expect(
					(await s.getMany([key("a"), key("b")])).entries.map((e) => e?.value ?? null),
				).toEqual([null, 2]);
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
				await s.put(k, { b: 1, a: { d: 2, c: 3 } }, never);
				const value = (await s.get(k)).entry?.value as Record<string, Record<string, number>>;
				expect(Object.keys(value)).toEqual(["a", "b"]);
				expect(Object.keys(value.a ?? {})).toEqual(["c", "d"]);
			});

			it("removes the entry when a mutation decides to", async () => {
				const s = await harness.open();
				const k = fresh()("a");
				await s.put(k, 1, never);
				expect(await mutate(s, k, () => ({ kind: "remove" }))).toEqual({
					kind: "done",
					value: null,
					version: null,
				});
				expect((await s.get(k)).entry).toBeNull();
			});

			it("reads a key and the keys it points to consistently", async () => {
				const s = await harness.open();
				const key = fresh();
				await s.put(key("index"), "target", never);
				await s.put(key("target"), { found: true }, never);
				const read = await getFollowing(s, key("index"), (entry) =>
					entry ? [key(entry.value as string)] : [],
				);
				expect("followed" in read && read.followed[0]?.value).toEqual({ found: true });
			});

			it("reads again when the first key moves before the keys it points to are read", async () => {
				const s = await harness.open();
				const key = fresh();
				await s.put(key("index"), "old", never);
				await s.put(key("old"), "was", never);
				await s.put(key("new"), "is", never);
				let follows = 0;
				const read = await getFollowing(s, key("index"), (entry) => {
					follows += 1;
					// Another client points the index elsewhere after the first read.
					if (follows === 1) void s.put(key("index"), "new", never);
					return entry ? [key(entry.value as string)] : [];
				});
				expect(follows).toBe(2);
				expect("followed" in read && read.followed[0]?.value).toBe("is");
			});

			it("answers a mutation that keeps with the entry, and reads again when a removal loses a race", async () => {
				const s = await harness.open();
				const key = fresh();
				const version = versionOf(await s.put(key("a"), 1, never));
				expect(await mutate(s, key("a"), () => ({ kind: "keep" }))).toEqual({
					kind: "done",
					value: 1,
					version,
				});
				let runs = 0;
				const removed = await mutate(s, key("a"), () => {
					runs += 1;
					// Another client rewrites the entry after the first read.
					if (runs === 1) void s.put(key("a"), 2, never);
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
				const first = versionOf(await s.put(key("a"), 1, never));
				seen.add(first);
				await s.removeIf(key("a"), { value: 1 });
				seen.add(versionOf(await s.put(key("a"), 1, never)));
				expect((await s.replaceIf(key("a"), first, 2, never)).kind).toBe("conflict");
				const kept = versionOf(await s.put(key("long"), 1, never));
				seen.add(kept);
				for (let i = 0; i < 5; i++)
					seen.add(versionOf(await s.put(key("short"), i, { expiry: { kind: "after", ms: 100 } })));
				await sleep(300);
				for (let i = 0; i < 5; i++) seen.add(versionOf(await s.put(key("short"), i, never)));
				expect(seen.size).toBe(13);
				expect((await s.replaceIf(key("long"), kept, 2, never)).kind).toBe("written");
			});

			it.runIf(harness.restart !== undefined)(
				"never repeats a version across a restart",
				async () => {
					const s = await harness.open();
					const k = fresh()("a");
					const before = [versionOf(await s.put(k, 1, never)), versionOf(await s.put(k, 2, never))];
					await harness.restart?.();
					const written = await eventually(() => s.put(k, 3, never), 100);
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
					const seen = [versionOf(await s.put(k, 1, never))];
					await harness.stopReplicas?.();
					await s.put(k, 2, never).catch(() => undefined);
					const unconfirmed = (await s.get(k)).entry?.version;
					if (unconfirmed) seen.push(unconfirmed);
					const undo = await harness.failover?.();
					try {
						const written = await eventually(() => s.put(k, 3, never), 100);
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
					const seen = new Set<Version>([versionOf(await s.put(k, 1, never))]);
					const promote = async () => {
						const undo = await harness.failover?.();
						try {
							const written = await eventually(() => s.put(k, 2, never), 100);
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
				await s.put(key("short"), 1, { expiry: { kind: "after", ms: 150 } });
				await s.put(key("kept"), 1, { expiry: { kind: "after", ms: 150 } });
				await s.put(key("kept"), 2, { expiry: { kind: "keep" } });
				await s.put(key("long"), 1, { expiry: { kind: "after", ms: 150 } });
				await s.put(key("long"), 2, { expiry: { kind: "extend", ms: 5000 } });
				await s.put(key("forever"), 1, never);
				await s.put(key("forever"), 2, { expiry: { kind: "extend", ms: 10 } });
				await sleep(400);
				expect((await s.get(key("short"))).entry).toBeNull();
				expect((await s.get(key("kept"))).entry).toBeNull();
				expect((await s.get(key("long"))).entry?.value).toBe(2);
				expect((await s.get(key("forever"))).entry?.expiresAt).toBeNull();
			});

			it("holds an entry only while the store clock is before its expiry, reads and keep-writes alike", async () => {
				const s = await harness.open();
				const key = fresh();
				const { now } = await s.get(key("probe"));
				const at = now + 30;
				await s.put(key("a"), 1, { expiry: { kind: "at", at } });
				await expectPresentUntil(at, async () => {
					const read = await s.get(key("a"));
					return { now: read.now, present: read.entry !== null };
				});
				const { now: later } = await s.get(key("probe"));
				await s.put(key("b"), 1, { expiry: { kind: "at", at: later } });
				expect((await s.get(key("b"))).entry).toBeNull();
			});

			it("expires at the time given, and treats expired entries as absent everywhere", async () => {
				const s = await harness.open();
				const key = fresh();
				const { now } = await s.get(key("x"));
				await s.put(key("at"), 1, { expiry: { kind: "at", at: now + 150 } });
				expect((await s.get(key("at"))).entry?.value).toBe(1);
				const version = versionOf(
					await s.put(key("gone"), 1, { expiry: { kind: "after", ms: 150 } }),
				);
				await s.put(key("w"), 1, { expiry: { kind: "after", ms: 150 } });
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
				expect((await s.put(key("past"), 1, { expiry: { kind: "at", at: now } })).kind).toBe(
					"written",
				);
				expect((await s.get(key("past"))).entry).toBeNull();
				await s.put(key("doc"), { a: 1, b: 2 }, never);
				expect((await s.removeIf(key("doc"), { value: { b: 2, a: 1 } })).kind).toBe("removed");
			});
		});

		describe("deadlines and idempotency marks", () => {
			it("refuses put, putIfAbsent, replaceIf, removeIf, batch and mutate past their deadline on the store clock", async () => {
				const s = await harness.open();
				const key = fresh();
				const version = versionOf(await s.put(key("a"), 1, never));
				const { now } = await s.get(key("a"));
				const late = { deadline: now - 1 };
				expect((await s.put(key("b"), 1, { ...never, ...late })).kind).toBe("late");
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
				await s.put(k, 1, never);
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
				await s.put(key("a"), 1, never);
				await s.put(key("b"), 1, never);
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
				expect((await s.put(key("a"), { x: 1, y: 2 }, { ...never, ...mark("m1") })).kind).toBe(
					"written",
				);
				expect((await s.put(key("a"), { y: 2, x: 1 }, { ...never, ...mark("m1") })).kind).toBe(
					"written",
				);
				expect((await s.put(key("a"), { x: 1, y: 3 }, { ...never, ...mark("m1") })).kind).toBe(
					"reused",
				);
				expect((await s.put(other("a"), 1, { ...never, ...mark("m1") })).kind).toBe("written");
				const version = versionOf(await s.put(key("v"), 1, never));
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
				expect((await s.put(key("a"), 1, mark)).kind).toBe("written");
				expect((await s.putIfAbsent(key("a"), 1, mark)).kind).toBe("reused");
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
				await s.put(key("a"), "only", never);
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
				await s.put(k, 1, never);
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
					await s.put(key("a"), "only", never);
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
			it("writes and reads several keys of a partition as one, under concurrent connections", async () => {
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
				const readers = race(30, [t, s], (store) => store.getMany([key("a"), key("b")]));
				await writers;
				for (const read of await readers) {
					expect(read.entries[0]?.value ?? null).toEqual(read.entries[1]?.value ?? null);
				}
			});

			it("takes an entry exactly once among racing takers on two connections", async () => {
				const [s, t] = await both();
				const k = fresh()("a");
				await s.put(k, "only", never);
				const results = await race(20, [s, t], (store) => store.take(k));
				expect(results.filter((r) => r.kind === "taken")).toHaveLength(1);
			});

			it("lets exactly one racing writer in when writing if absent or on a version", async () => {
				const [s, t] = await both();
				const key = fresh();
				const absent = await race(20, [s, t], (store, i) => store.putIfAbsent(key("a"), i, never));
				expect(absent.filter((r) => r.kind === "written")).toHaveLength(1);
				const version = versionOf(await s.put(key("b"), 0, never));
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
				await s.put(k, { a: 0, b: 0 }, never);
				let runs = 0;
				let rival: Promise<unknown> = Promise.resolve();
				const result = await mutate(s, k, (entry) => {
					runs += 1;
					const doc = entry?.value as { a: number; b: number };
					// Another client rewrites b after the first read and before the write.
					if (runs === 1) rival = s.put(k, { ...doc, b: 1 }, never);
					return { kind: "write", value: { ...doc, a: 1 }, expiry: { kind: "keep" } };
				});
				await rival;
				expect(result.kind).toBe("done");
				expect(runs).toBeGreaterThan(1);
				expect((await s.get(k)).entry?.value).toEqual({ a: 1, b: 1 });
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

		describe("sets", () => {
			it("drops a set member whose score the store clock has reached", async () => {
				const s = await harness.open();
				const key = fresh();
				const { now } = await s.get(key("probe"));
				const at = now + 30;
				await s.setAdd(key("set"), "m", at, { cap: 10, expiry: never.expiry });
				await expectPresentUntil(at, async () => {
					const read = await s.setMembers(key("set"));
					return { now: read.now, present: read.members.some((m) => m.member === "m") };
				});
			});

			it("keeps the highest score, evicts the lowest over the cap and prunes on the store clock", async () => {
				const s = await harness.open();
				const k = fresh()("set");
				const { now } = await s.get(k);
				const options = { cap: 2, expiry: { kind: "after", ms: 60_000 } } as const;
				await s.setAdd(k, "a", now + 50_000, options);
				await s.setAdd(k, "a", now + 10_000, options);
				await s.setAdd(k, "b", now + 20_000, options);
				const added = await s.setAdd(k, "c", now + 30_000, options);
				expect(added.evicted).toEqual(["b"]);
				const { now: soon } = await s.get(k);
				await s.setAdd(k, "d", soon + 300, { cap: 3, expiry: { kind: "after", ms: 60_000 } });
				await sleep(400);
				const read = await s.setMembers(k);
				expect(read.members.map((m) => [m.member, m.score - now])).toEqual([
					["a", 50_000],
					["c", 30_000],
				]);
			});

			it("gives a new set its expiry, even when extending or when every member had expired", async () => {
				const s = await harness.open();
				const key = fresh();
				const { now } = await s.get(key("x"));
				await s.setAdd(key("extended"), "m", now + 600_000, {
					cap: 5,
					expiry: { kind: "extend", ms: 150 },
				});
				await s.setAdd(key("revived"), "old", now + 100, {
					cap: 5,
					expiry: { kind: "after", ms: 600_000 },
				});
				await sleep(200);
				await s.setAdd(key("revived"), "new", now + 600_000, {
					cap: 5,
					expiry: { kind: "after", ms: 150 },
				});
				await sleep(400);
				expect((await s.setMembers(key("extended"))).members).toEqual([]);
				expect((await s.setMembers(key("revived"))).members).toEqual([]);
			});

			it("keeps a set without expiry when a later add asks for one", async () => {
				const s = await harness.open();
				const k = fresh()("set");
				const { now } = await s.get(k);
				await s.setAdd(k, "a", now + 600_000, { cap: 5, expiry: { kind: "never" } });
				await s.setAdd(k, "b", now + 600_000, { cap: 5, expiry: { kind: "after", ms: 100 } });
				await sleep(300);
				expect((await s.setMembers(k)).members.map((m) => m.member)).toEqual(["a", "b"]);
			});

			it("keeps a long set expiry when a later add asks for a short one", async () => {
				const s = await harness.open();
				const k = fresh()("set");
				const { now } = await s.get(k);
				await s.setAdd(k, "a", now + 600_000, { cap: 5, expiry: { kind: "after", ms: 600_000 } });
				await s.setAdd(k, "b", now + 600_000, { cap: 5, expiry: { kind: "after", ms: 100 } });
				await sleep(300);
				expect((await s.setMembers(k)).members.map((m) => m.member)).toEqual(["a", "b"]);
			});

			it("evicts, among equal lowest scores, the member first in code point order", async () => {
				const s = await harness.open();
				const k = fresh()("set");
				const { now } = await s.get(k);
				const options = { cap: 2, expiry: { kind: "never" } } as const;
				await s.setAdd(k, "b", now + 50_000, options);
				await s.setAdd(k, "c", now + 50_000, options);
				expect((await s.setAdd(k, "a", now + 50_000, options)).evicted).toEqual(["a"]);
			});

			it("removes a member from a set", async () => {
				const s = await harness.open();
				const k = fresh()("set");
				const { now } = await s.get(k);
				await s.setAdd(k, "a", now + 600_000, { cap: 5, expiry: { kind: "never" } });
				await s.setAdd(k, "b", now + 600_000, { cap: 5, expiry: { kind: "never" } });
				await s.setRemove(k, "a");
				expect((await s.setMembers(k)).members.map((m) => m.member)).toEqual(["b"]);
			});
		});

		describe("scanning a space", () => {
			const walk = async (s: Store, target: Space, between?: () => Promise<void>) => {
				const scan = s.scan?.bind(s);
				if (!scan) throw new Error("this store cannot scan");
				const seen = new Map<string, number>();
				let cursor: string | undefined;
				do {
					const page = await scan(target, cursor);
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

			it("lists each live value's key in the space, over pages, and no counter, set or other space", async (ctx) => {
				const s = await harness.open();
				// Until every implementation scans.
				if (!s.scan) return ctx.skip();
				const live = Array.from({ length: 250 }, (_, i) => fresh(space, `q${i % 7}`)(`k${i}`));
				for (const k of live) await s.put(k, 1, never);
				const { now } = await s.get(fresh()("probe"));
				const ends = now + 30;
				await s.put(fresh()("gone"), 1, { expiry: { kind: "at", at: ends } });
				while ((await s.now()) <= ends) await sleep(5);
				await s.put(fresh(replicated)("elsewhere"), 1, never);
				await s.count(fresh()("counted"), { ms: 60_000, limit: 5 });
				await s.setAdd(fresh()("set"), "m", now + 60_000, { cap: 1, expiry: never.expiry });
				const seen = await walk(s, space);
				expect([...seen.keys()].sort()).toEqual(live.map((k) => `${k.partition}/${k.name}`).sort());
				expect([...(await walk(s, replicated)).keys()]).toHaveLength(1);
				expect([...(await walk(await harness.open(), space)).keys()]).toEqual([]);
			});

			it("lists every key that lives through the walk, whatever is written or removed meanwhile", async (ctx) => {
				const s = await harness.open();
				// Until every implementation scans.
				if (!s.scan) return ctx.skip();
				const kept = Array.from({ length: 120 }, (_, i) => fresh(space, "w")(`kept${i}`));
				const dropped = Array.from({ length: 120 }, (_, i) => fresh(space, "w")(`dropped${i}`));
				for (const k of [...kept, ...dropped]) await s.put(k, 1, never);
				let n = 0;
				const seen = await walk(s, space, async () => {
					const k = dropped[n];
					if (k) await s.removeIf(k, { value: 1 });
					await s.put(fresh(space, "w")(`added${n++}`), 1, never);
				});
				for (const k of kept) expect(seen.get(`w/${k.name}`), k.name).toBeGreaterThanOrEqual(1);
			});

			it("refuses a space that is not declared", async (ctx) => {
				const s = await harness.open();
				// Until every implementation scans.
				if (!s.scan) return ctx.skip();
				await expect(s.scan?.({ name: "undeclared", guarantees: [] })).rejects.toThrow();
			});
		});

		describe("input checks", () => {
			it("refuses times, durations and limits that are not whole numbers in range", async () => {
				const s = await harness.open();
				const k = fresh()("a");
				await expect(s.put(k, 1, { expiry: { kind: "after", ms: 1.5 } })).rejects.toThrow(
					TypeError,
				);
				await expect(s.put(k, 1, { expiry: { kind: "at", at: -1 } })).rejects.toThrow(TypeError);
				await expect(s.put(k, 1, { ...never, deadline: 0.5 })).rejects.toThrow(TypeError);
				await expect(
					s.batch([], [{ key: k, put: 1, expiry: { kind: "after", ms: Number.NaN } }]),
				).rejects.toThrow(TypeError);
				await expect(s.count(k, { ms: 10.5, limit: 1 })).rejects.toThrow(TypeError);
				await expect(s.setAdd(k, "m", 1.5, { cap: 1, expiry: { kind: "never" } })).rejects.toThrow(
					TypeError,
				);
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
					await expect(s.put(key("a"), bad as never, never)).rejects.toThrow(TypeError);
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
				expect((await s.getMany([key("a"), key("b"), key("c")])).entries).toEqual([
					null,
					null,
					null,
				]);
				await expect(
					s.put(
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
				await expect(s.setAdd(k, "m", 1, { cap: 1.5, expiry: { kind: "never" } })).rejects.toThrow(
					TypeError,
				);
				await expect(s.take(k, { deadline: -1 })).rejects.toThrow(TypeError);
			});

			it("refuses options with unknown or hidden properties", async () => {
				const s = await harness.open();
				const k = fresh()("a");
				await expect(s.put(k, 1, { ...never, deadlin: 1 } as never)).rejects.toThrow(TypeError);
				const hidden = Object.defineProperty({ ...never }, "deadline", {
					value: 0,
					enumerable: false,
				});
				await expect(s.put(k, 1, hidden)).rejects.toThrow(TypeError);
				await expect(s.count(k, { ms: 1000, limit: 1, extra: 1 } as never)).rejects.toThrow(
					TypeError,
				);
			});

			it("takes only well-formed strings and keeps non-ASCII keys and members apart, in code point order", async () => {
				const s = await harness.open();
				const key = fresh();
				const lone = "\uD800";
				await expect(s.put(key(lone), 1, never)).rejects.toThrow(TypeError);
				await expect(s.put(key("a"), lone, never)).rejects.toThrow(TypeError);
				await expect(s.put(key("a"), { [lone]: 1 }, never)).rejects.toThrow(TypeError);
				await expect(s.put(key("a"), 1, { ...never, idempotency: lone })).rejects.toThrow(
					TypeError,
				);
				await expect(
					s.setAdd(key("set"), lone, 1, { cap: 1, expiry: { kind: "never" } }),
				).rejects.toThrow(TypeError);
				await s.put(key("é😀"), "é😀", never);
				expect((await s.get(key("é😀"))).entry?.value).toBe("é😀");
				expect((await s.get(key("e😀"))).entry).toBeNull();
				const { now } = await s.get(key("x"));
				for (const m of ["😀", "é", "a", "￿"]) {
					await s.setAdd(key("set"), m, now + 600_000, { cap: 10, expiry: { kind: "never" } });
				}
				expect((await s.setMembers(key("set"))).members.map((m) => m.member)).toEqual([
					"a",
					"é",
					"￿",
					"😀",
				]);
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
					await expect(s.put(key("a"), bad as never, never)).rejects.toThrow(TypeError);
				}
				const sneaky = Object.defineProperty({ space, partition: "p" }, "name", {
					get: () => "a",
					enumerable: true,
				});
				await expect(s.get(sneaky as Key)).rejects.toThrow(TypeError);
				await s.put(key("z"), -0, never);
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
					"time past the last date": () => s.put(k, 1, { expiry: { kind: "at", at: 8.65e15 } }),
					"limit past its range": () => s.count(k, { ms: 1000, limit: 1_000_000_001 }),
					"zero duration": () => s.put(k, 1, { expiry: { kind: "after", ms: 0 } }),
					"unknown expiry": () => s.put(k, 1, { expiry: { kind: "forever" } as never }),
					"option with a getter": () => s.put(k, 1, hiddenDeadline),
					"batch option": () => s.batch([], [], { deadline: 0.5 }),
					"symbol key in a value": () => s.put(k, { [Symbol("x")]: 1 } as never, never),
					"array subclass": () => s.put(k, Items.from([1]) as never, never),
					"array with a trailing hole": () => s.put(k, trailingHole, never),
					"array with a hole and a property": () => s.put(k, holeAndExtra, never),
					"array with a symbol": () => s.put(k, Object.assign([1], { [Symbol("x")]: 1 }), never),
					"value nested too deeply": () => s.put(k, deep as never, never),
					"value expected by a removal": () => s.removeIf(k, { value: new Date(0) as never }),
					"empty condition version": () => s.batch([{ key: k, version: "" }], []),
					"condition with neither": () => s.batch([{ key: k } as never], []),
					"empty member removed": () => s.setRemove(k, ""),
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
					await s.put(at("a"), 1, never);
					await s.put(at("b"), 1, never);
					const version = versionOf(await s.put(at("r"), 1, never));
					const vVersion = versionOf(await s.put(at("v"), 1, never));
					await s.put(at("w"), 1, never);
					await s.setAdd(at("set2"), "m", Date.now() + 600_000, {
						cap: 5,
						expiry: { kind: "never" },
					});
					const undo = await harness.stopReplicas?.();
					try {
						expect((await s.put(fresh()("plain"), 1, never)).kind).toBe("written");
						const unconfirmed: Record<string, () => Promise<unknown>> = {
							put: () => s.put(at("a"), 2, never),
							putIfAbsent: () => s.putIfAbsent(at("new"), 2, never),
							replaceIf: () => s.replaceIf(at("v"), vVersion, 2, never),
							"removeIf by value": () => s.removeIf(at("w"), { value: 1 }),
							setRemove: () => s.setRemove(at("set2"), "m"),
							"put with a key that hides the guarantee": () => s.put(disguised("c"), 2, never),
							take: () => s.take(at("b")),
							"removeIf by version": () => s.removeIf(at("r"), { version }),
							batch: () => s.batch([], [{ key: at("d"), put: 1, expiry: { kind: "never" } }]),
							count: () => s.count(at("hits"), { ms: 10_000, limit: 5 }),
							setAdd: () =>
								s.setAdd(at("set"), "m", Date.now() + 600_000, {
									cap: 5,
									expiry: { kind: "never" },
								}),
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
					await s.put(k, "code", never);
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
					const version = versionOf(await s.put(at("a"), 1, never));
					await s.put(plain("a"), 1, never);
					const { now } = await s.get(at("a"));
					await s.setAdd(at("set"), "m", now + 600_000, { cap: 5, expiry: { kind: "never" } });
					await s.count(at("hits"), { ms: 60_000, limit: 1 });
					const undo = await harness.stopReplicas?.();
					try {
						const unconfirmed: Record<string, () => Promise<unknown>> = {
							get: () => s.get(at("a")),
							getMany: () => s.getMany([at("a"), at("b")]),
							setMembers: () => s.setMembers(at("set")),
							"putIfAbsent, exists": () => s.putIfAbsent(at("a"), 2, never),
							"replaceIf, conflict": () => s.replaceIf(at("a"), `${version}x`, 2, never),
							"take, missing": () => s.take(at("none")),
							"removeIf, missing": () => s.removeIf(at("none"), { value: 1 }),
							"count, limited": () => s.count(at("hits"), { ms: 60_000, limit: 1 }),
							"batch, conflict": () => s.batch([{ key: at("a"), absent: true }], []),
							"removeIf, conflict": () => s.removeIf(at("a"), { value: 99 }),
							"replaceIf, missing": () => s.replaceIf(at("none"), version, 2, never),
							"put, late": () => s.put(at("late"), 1, { ...never, deadline: now - 1 }),
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
						await expect(s.put(k, 1, never)).rejects.toMatchObject({ name: "Unavailable" });
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
					await s.put(other, 1, never);
					const undo = await harness.stopReplicas?.();
					try {
						const waiting = s.put(k, 1, never).then(
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
					await s.put(earlier, "kept", never);
					expect((await s.put(later, 1, never)).kind).toBe("written");
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
