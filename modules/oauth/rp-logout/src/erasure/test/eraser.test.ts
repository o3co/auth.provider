import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { recordingLog } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import { describe, expect, it } from "vitest";
import { bodyOf, idOf } from "../../notice-body/notice-body.ts";
import type { NoticeBodies } from "../../store.ts";
import { noticesEraser } from "../eraser.ts";

const signal = new AbortController().signal;
const walk: Walk = { sweep: async () => ({ keys: [], server: "one" }) };
const clock = { now: () => 1000 };
const notice = (session: string, jti: string) =>
	({ client: "app", session, subject: "alice", until: 60_000, jti }) as const;

/** The stores in memory, the bodies erasing `removed` and migrating by `reading`, noting what is asked. */
const placed = (removed: string[], erasing = true) => {
	const stand = memoryRecords<string>(clock.now, { shards: 1, perShard: 100 });
	const pending = memoryRecords<string>(clock.now, { shards: 1, perShard: 100 }).deferred;
	const read: string[] = [];
	const bodies: NoticeBodies = {
		create: async (id, body, ms) => stand.records.create(id, body, ms),
		read: stand.records.read,
		remove: stand.records.remove,
		...(erasing && {
			erase: async (_subject, _signal, eachRemoved) => {
				for (const body of removed) eachRemoved?.(body);
				return { kind: "erased" } as unknown as SpaceReport;
			},
			migrate: async (_w: Walk, reading: SubjectReading) => {
				for (const body of removed) read.push((await reading(idOf(body), body)).kind);
				return { kind: "migrated" } as unknown as MigrationReport;
			},
		}),
	};
	return { stores: { bodies, queue: stand.deferred, pending }, read, stand };
};

describe("rp-logout's eraser", () => {
	it("states that it cannot erase where the bodies lack the ports, answering empty reports", async () => {
		const eraser = noticesEraser(placed([], false).stores, recordingLog().log, clock);
		expect([eraser.name, eraser.erasable, eraser.after]).toEqual(["rp-logout", false, undefined]);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.migrate(walk, signal)).toEqual([]);
	});

	it("counts the distinct sessions among the bodies it removes, one more for each that does not read", async () => {
		const removed = [
			bodyOf(notice("h-1", "a")),
			bodyOf(notice("h-1", "b")),
			bodyOf(notice("h-2", "c")),
			"not a body",
		];
		const eraser = noticesEraser(placed(removed).stores, recordingLog().log, clock);
		expect((await eraser.online("alice", signal)).logoutGaps).toBe(3);
		expect((await eraser.window(["alice", "bob"], walk, signal)).logoutGaps).toBe(6);
	});

	it("drains the 0.19 notices into bodies and entries, then migrates the bodies by the subject each names", async () => {
		const p = placed([bodyOf(notice("h-1", "a")), "not a body"]);
		const kept = JSON.stringify({ ...notice("h-3", "d"), after: 500 });
		await p.stores.pending.add(kept);
		await p.stores.pending.add(JSON.stringify({ ...notice("h-4", "e"), until: 1 }));
		const eraser = noticesEraser(p.stores, recordingLog().log, clock);
		expect(await eraser.migrate(walk, signal)).toEqual([{ kind: "migrated" }]);
		expect(p.read).toEqual(["subject", "unreadable"]);
		const id = idOf(bodyOf(notice("h-3", "d")));
		expect(await p.stores.bodies.read(id)).toBe(bodyOf(notice("h-3", "d")));
		const left: string[] = [];
		await p.stores.pending.each(async (n) => void left.push(n));
		expect(left).toEqual([]);
	});

	it("stops, after the bodies' own migrate, where a 0.19 notice is not moved, and on an abort", async () => {
		const p = placed([]);
		await p.stores.pending.add(JSON.stringify(notice("h-5", "f")));
		const failing = {
			...p.stores,
			queue: { ...p.stores.queue, add: async () => Promise.reject(new Error("full")) },
		};
		const answers = await noticesEraser(failing, recordingLog().log, clock).migrate(walk, signal);
		expect(answers).toEqual([
			{ kind: "migrated" },
			{ kind: "owner-stopped", reason: expect.stringContaining("not moved yet") },
		]);
		const stop = new AbortController();
		stop.abort();
		const aborted = await noticesEraser(p.stores, recordingLog().log, clock).migrate(
			walk,
			stop.signal,
		);
		expect(aborted.at(-1)).toEqual({ kind: "owner-stopped", reason: "aborted" });
	});
});
