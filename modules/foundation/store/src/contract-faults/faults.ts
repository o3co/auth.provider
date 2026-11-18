import { describe, expect, it } from "vitest";
import {
	type ContractKit,
	eventually,
	overwrite,
	type StoreHarness,
	sleep,
	versionOf,
} from "../contract-harness/harness.ts";

/** The store contract's replication faults: replicas that do not acknowledge, lost replies, restarts and failover. */
export function faultsContract(harness: StoreHarness, kit: ContractKit): void {
	const { replicated, confirmed, fresh, never, partition: next } = kit;
	describe("replication faults", () => {
		it.runIf(harness.stopReplicas !== undefined)(
			"answers unavailable when a replicated space's write is not acknowledged by the replicas",
			async () => {
				const s = await harness.open();
				const partition = next();
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
				const partition = next();
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
}
