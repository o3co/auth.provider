import type { MigrationReport, SpaceReport } from "@mod/erasure-extensions";
import { expect, it } from "vitest";
import type { NoticeBodies } from "../../store.ts";
import { portsOf, portsRefused } from "../ports.ts";

const bodies = { create: async () => "created" as const } as unknown as NoticeBodies;
const erase = async () => ({}) as SpaceReport;
const migrate = async () => ({}) as MigrationReport;

it("takes the bodies' erase and migrate both or neither, refusing a part", () => {
	expect([portsRefused(bodies), portsOf(bodies)]).toEqual([undefined, undefined]);
	expect(portsRefused({ ...bodies, erase, migrate })).toBeUndefined();
	expect(portsOf({ ...bodies, erase, migrate })).toBeDefined();
	for (const part of [
		{ ...bodies, erase },
		{ ...bodies, migrate },
	]) {
		expect(portsRefused(part)).toContain("both, or neither");
		expect(portsOf(part)).toBeUndefined();
	}
});
