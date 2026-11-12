import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { describe, expect, it } from "vitest";
import type { CodeStore, RedemptionRecords } from "../../store.ts";
import { type ErasableStores, portsOf, portsRefused } from "../ports.ts";

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

describe("code-grant's store ports", () => {
	it("takes all four or none, refusing a part, and gives the set only whole", () => {
		const asked: string[] = [];
		const [codes, redemptionRecords] = [
			erasing(plainCodes, "codes", asked),
			erasing(plainRecords, "records", asked),
		];
		expect(portsRefused({ codes: plainCodes, redemptionRecords: plainRecords })).toBeUndefined();
		expect(portsRefused({ codes, redemptionRecords })).toBeUndefined();
		const { migrate: _codesMigrate, ...codesHalf } = codes;
		const { erase: _recordsErase, ...recordsHalf } = redemptionRecords;
		const parts: ErasableStores[] = [
			{ codes, redemptionRecords: plainRecords },
			{ codes: plainCodes, redemptionRecords },
			{ codes: codesHalf, redemptionRecords },
			{ codes, redemptionRecords: recordsHalf },
		];
		for (const part of parts) {
			expect(portsRefused(part)).toMatch(/all four, or none/);
			expect(portsOf(part)).toBeUndefined();
		}
		expect(portsOf({ codes, redemptionRecords })).toBeDefined();
	});
});
