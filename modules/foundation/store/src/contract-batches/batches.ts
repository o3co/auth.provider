import { describe, expect, it } from "vitest";
import type { Key, Space, Store } from "../contract.ts";
import {
	type ContractKit,
	overwrite,
	race,
	type StoreHarness,
	sleep,
	versionOf,
} from "../contract-harness/harness.ts";

/** The store contract's batches across partitions and spaces, counting, and reads of several keys and a batch's time. */
export function batchesContract(harness: StoreHarness, kit: ContractKit): void {
	const { replicated, twin, fresh, never, both } = kit;
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
			const { at, ...empty } = (await batchAcross([], [], {
				deadline: now + 60_000,
				idempotency: "empty",
			})) as { at?: number };
			expect(empty).toEqual({ kind: "committed", versions: [] });
			if (at !== undefined) expect(at).toEqual(expect.any(Number));
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
			const undeclared: Space = { name: "nowhere", guarantees: [], subjectData: "none" };
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
			const first = await batchAcross([{ key: c, absent: true }], [put(a, 1), put(b, 1)], options);
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
			const results = await race(30, [s, t], (store) => store.count(k, { ms: 10_000, limit: 10 }));
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
			// A window long enough that a slow caller's second hit still falls in it, waited out on
			// the store clock its answer names, never the caller's.
			const window = { ms: 1_000, limit: 1 };
			const first = await s.count(k, window);
			expect(first.kind).toBe("counted");
			expect((await s.count(k, window)).kind).toBe("limited");
			// Past resetAt, not at it: a backend may keep the window through resetAt's own millisecond.
			const resetAt = "resetAt" in first ? first.resetAt : Number.NaN;
			const giveUp = Date.now() + window.ms + 5_000;
			let now = await s.now();
			while (now <= resetAt && Date.now() < giveUp) {
				await sleep(20);
				now = await s.now();
			}
			expect(now > resetAt, "the store clock did not pass resetAt").toBe(true);
			expect(await s.count(k, window)).toMatchObject({ kind: "counted", count: 1 });
		});
	});

	describe("reads of several keys, and a batch's time", () => {
		it("reads several keys in the order asked, none where absent", async (ctx) => {
			const s = await harness.open();
			if (!s.getMany) return ctx.skip();
			const key = fresh();
			await s.putIfAbsent(key("a"), "a", never);
			await s.putIfAbsent(key("c"), "c", never);
			const reads = await s.getMany([key("c"), key("b"), key("a")]);
			expect(reads.map((r) => r.entry?.value ?? null)).toEqual(["c", null, "a"]);
		});

		it("tells the store time a batch committed at, where it tells one, and the same on a resend", async () => {
			const s = await harness.open();
			const key = fresh();
			const before = await s.now();
			const write = [{ key: key("a"), put: 1, expiry: { kind: "never" } }] as const;
			const first = await s.batch([], write, { idempotency: "timed" });
			if (first.kind !== "committed" || first.at === undefined) return;
			expect(first.at).toBeGreaterThanOrEqual(before);
			expect(first.at).toBeLessThanOrEqual(await s.now());
			expect(await s.batch([], write, { idempotency: "timed" })).toEqual(first);
		});
	});
}
