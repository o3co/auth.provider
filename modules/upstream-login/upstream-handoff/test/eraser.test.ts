import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { describe, expect, it } from "vitest";
import { heldLoginEraser } from "../src/eraser.ts";
import type { HeldLoginStore } from "../src/store.ts";

const signal = new AbortController().signal;
const walk: Walk = { sweep: async () => ({ keys: [], server: "one" }) };
const plain = {
	save: async () => "created" as const,
	update: async () => undefined,
	remove: async () => {},
};
const fenced = { kind: "fenced", space: "held" } as unknown as SpaceReport;

describe("upstream-handoff's eraser", () => {
	it("states that it cannot erase where the Store lacks the ports, answering empty reports", async () => {
		const eraser = heldLoginEraser(plain as HeldLoginStore);
		expect([eraser.name, eraser.erasable]).toEqual(["upstream-handoff", false]);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.window(["alice"], walk, signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.migrate(walk, signal)).toEqual([]);
	});

	it("passes on the Store's report, each subject in a window, and migrates reading no held login", async () => {
		const asked: string[] = [];
		const held = {
			...plain,
			erase: async (subject: string) => {
				asked.push(`erase ${subject}`);
				return fenced;
			},
			migrate: async (_walk: Walk, reading: SubjectReading) => {
				asked.push(
					await reading("carry", {}).then(
						() => "read",
						() => "refused to read",
					),
				);
				return { kind: "migrated", space: "held", indexed: 0, removed: 0 } as MigrationReport;
			},
		};
		const eraser = heldLoginEraser(held as HeldLoginStore);
		expect(eraser.erasable).toBe(true);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [fenced], logoutGaps: 0 });
		expect((await eraser.window(["bob", "carol"], walk, signal)).reports).toEqual([fenced, fenced]);
		expect(await eraser.migrate(walk, signal)).toHaveLength(1);
		expect(asked).toEqual(["erase alice", "erase bob", "erase carol", "refused to read"]);
	});
});
