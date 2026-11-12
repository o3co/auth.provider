import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { describe, expect, it } from "vitest";
import type { CodeStore, RedemptionRecords } from "../../store.ts";
import { codeGrantEraser } from "../eraser.ts";

const signal = new AbortController().signal;
const walk: Walk = { sweep: async () => ({ keys: [], server: "one" }) };
const plainCodes = {
	nameOf: (code: string) => code,
	create: async () => "created" as const,
	update: async () => undefined,
} as CodeStore;
const plainRecords = {
	create: async () => "created" as const,
	read: async () => undefined,
	update: async () => undefined,
} as RedemptionRecords;

/** A place offering both ports, noting each call as `<space> <what>`. */
const erasing = <T extends object>(plain: T, space: string, asked: string[]) => ({
	...plain,
	erase: async (subject: string) => {
		asked.push(`${space} erase ${subject}`);
		return { kind: "fenced", space } as unknown as SpaceReport;
	},
	migrate: async (_walk: Walk, reading: SubjectReading) => {
		const read = await reading("carry", {}).then(
			() => "read",
			() => "refused to read",
		);
		asked.push(`${space} ${read}`);
		return { kind: "migrated", space, indexed: 0, removed: 0 } as MigrationReport;
	},
});

describe("code-grant's eraser", () => {
	it("states that it cannot erase where the places lack the ports, answering empty reports", async () => {
		const eraser = codeGrantEraser({ codes: plainCodes, redemptionRecords: plainRecords });
		expect([eraser.name, eraser.erasable]).toEqual(["code-grant", false]);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.window(["alice"], walk, signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.migrate(walk, signal)).toEqual([]);
	});

	it("passes on both places' reports, each subject in a window, and migrates reading no record", async () => {
		const asked: string[] = [];
		const codes = erasing(plainCodes, "codes", asked);
		const redemptionRecords = erasing(plainRecords, "records", asked);
		const eraser = codeGrantEraser({ codes, redemptionRecords });
		expect(eraser.erasable).toBe(true);
		expect((await eraser.online("alice", signal)).reports).toHaveLength(2);
		expect((await eraser.window(["bob"], walk, signal)).reports).toHaveLength(2);
		expect(await eraser.migrate(walk, signal)).toHaveLength(2);
		expect(asked).toEqual([
			"codes erase alice",
			"records erase alice",
			"codes erase bob",
			"records erase bob",
			"codes refused to read",
			"records refused to read",
		]);
	});
});
