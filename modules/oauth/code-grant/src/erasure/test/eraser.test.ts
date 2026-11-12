import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { describe, expect, it } from "vitest";
import type { CodeStore, RedemptionRecords } from "../../store.ts";
import { codeGrantEraser } from "../eraser.ts";
import { type ErasableStores, portsOf, portsRefused } from "../ports.ts";

const signal = new AbortController().signal;
const walk: Walk = { sweep: async () => ({ keys: [], server: "one" }) };
const plainCodes = {
	nameOf: (code: string) => code,
	save: async () => "created" as const,
	update: async () => undefined,
} as CodeStore;
const plainKept = {
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
		const eraser = codeGrantEraser({ codes: plainCodes, kept: plainKept });
		expect([eraser.name, eraser.erasable]).toEqual(["code-grant", false]);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.window(["alice"], walk, signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.migrate(walk, signal)).toEqual([]);
	});

	it("passes on both places' reports, each subject in a window, and migrates reading no record", async () => {
		const asked: string[] = [];
		const codes = erasing(plainCodes, "codes", asked);
		const kept = erasing(plainKept, "kept", asked);
		const eraser = codeGrantEraser({ codes, kept });
		expect(eraser.erasable).toBe(true);
		expect((await eraser.online("alice", signal)).reports).toHaveLength(2);
		expect((await eraser.window(["bob"], walk, signal)).reports).toHaveLength(2);
		expect(await eraser.migrate(walk, signal)).toHaveLength(2);
		expect(asked).toEqual([
			"codes erase alice",
			"kept erase alice",
			"codes erase bob",
			"kept erase bob",
			"codes refused to read",
			"kept refused to read",
		]);
	});
});

describe("code-grant's store ports", () => {
	it("takes all four or none, refusing a part, and gives the set only whole", () => {
		const asked: string[] = [];
		const [codes, kept] = [erasing(plainCodes, "codes", asked), erasing(plainKept, "kept", asked)];
		expect(portsRefused({ codes: plainCodes, kept: plainKept })).toBeUndefined();
		expect(portsRefused({ codes, kept })).toBeUndefined();
		const { migrate: _codesMigrate, ...codesHalf } = codes;
		const { erase: _keptErase, ...keptHalf } = kept;
		const parts: ErasableStores[] = [
			{ codes, kept: plainKept },
			{ codes: plainCodes, kept },
			{ codes: codesHalf, kept },
			{ codes, kept: keptHalf },
		];
		for (const part of parts) {
			expect(portsRefused(part)).toMatch(/all four, or none/);
			expect(portsOf(part)).toBeUndefined();
		}
		expect(portsOf({ codes, kept })).toBeDefined();
	});
});
