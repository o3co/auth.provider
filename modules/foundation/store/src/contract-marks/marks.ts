import { describe, expect, it } from "vitest";
import { mutate } from "../contract.ts";
import {
	type ContractKit,
	eventually,
	overwrite,
	race,
	type StoreHarness,
	sleep,
	versionOf,
} from "../contract-harness/harness.ts";

/** The store contract's deadlines and idempotency marks, and concurrent connections. */
export function marksContract(harness: StoreHarness, kit: ContractKit): void {
	const { fresh, never, both } = kit;
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
}
