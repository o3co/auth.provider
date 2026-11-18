import { describe, expect, it } from "vitest";
import { mutate, type Version, type WriteOptions } from "../contract.ts";
import {
	type ContractKit,
	eventually,
	expectPresentUntil,
	overwrite,
	type StoreHarness,
	sleep,
	versionOf,
} from "../contract-harness/harness.ts";

/** The store contract's reads and writes, versions and expiry of single keys. */
export function keysContract(harness: StoreHarness, kit: ContractKit): void {
	const { fresh, never } = kit;
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
			expect((await rewrite("forever", forever, { kind: "extend", ms: 10 })).kind).toBe("written");
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
			const ms = 1_000;
			const at = (await s.now()) + ms;
			await overwrite(s, key("at"), 1, { expiry: { kind: "at", at } });
			// Held or not by the store clock the read names, never by how long the caller took.
			const heldUntil = async (name: string, until: number) => {
				const read = await s.get(key(name));
				expect([read.now, read.entry?.value]).toEqual([read.now, read.now < until ? 1 : undefined]);
			};
			await heldUntil("at", at);
			const version = versionOf(
				await overwrite(s, key("gone"), 1, { expiry: { kind: "after", ms } }),
			);
			// Written after `before`, so it expires no earlier than `before + ms`.
			const before = await s.now();
			await overwrite(s, key("w"), 1, { expiry: { kind: "after", ms } });
			await heldUntil("w", before + ms);
			// Every expiry above ends by `end`, as each was written before this read.
			const end = (await s.now()) + ms;
			const giveUp = Date.now() + ms + 5_000;
			let now = await s.now();
			while (now <= end && Date.now() < giveUp) {
				await sleep(20);
				now = await s.now();
			}
			expect(now > end, "the store clock did not pass the expiries").toBe(true);
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
			expect((await s.putIfAbsent(key("past"), 1, { expiry: { kind: "at", at: now } })).kind).toBe(
				"written",
			);
			expect((await s.get(key("past"))).entry).toBeNull();
			await overwrite(s, key("doc"), { a: 1, b: 2 }, never);
			expect((await s.removeIf(key("doc"), { value: { b: 2, a: 1 } })).kind).toBe("removed");
		});
	});
}
