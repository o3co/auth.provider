import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { describe, expect, it } from "vitest";
import type { FamilySubject, FamilySubjects, Selection } from "../../contract.ts";
import type { SelectionRecords } from "../../store.ts";
import { stored } from "../../stored.ts";
import { selectionEraser } from "../eraser.ts";
import { portsRefused } from "../ports.ts";
import { selectionSubjectOf } from "../reading.ts";

const signal = new AbortController().signal;
const walk: Walk = { sweep: async () => ({ keys: [], server: "one" }) };
const plain = {
	create: async () => "created" as const,
	read: async () => undefined,
} as SelectionRecords;
const target = { names: [], constraints: [{ name: "email", value: "a@example.com" }] };
const selection: Selection = { idToken: target, userinfo: target };
const families = (answer: () => Promise<FamilySubject>): FamilySubjects => ({ subjectOf: answer });

describe("claims-selection's eraser", () => {
	it("states that it cannot erase where the store lacks the ports, answering empty reports", async () => {
		const eraser = selectionEraser(plain, undefined);
		expect([eraser.name, eraser.erasable, eraser.after]).toEqual([
			"claims-selection",
			false,
			undefined,
		]);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.window(["alice"], walk, signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.migrate(walk, signal)).toEqual([]);
	});

	it("passes on the store's reports, each subject in a window, migrating with its reading", async () => {
		const asked: string[] = [];
		const records = {
			...plain,
			erase: async function (this: unknown, subject: string) {
				asked.push(`erase ${subject} ${this === records}`);
				return { kind: "erased" } as unknown as SpaceReport;
			},
			migrate: async (_walk: Walk, reading: SubjectReading) => {
				asked.push(`read ${(await reading("t.tok", stored.target(target, "alice"))).kind}`);
				return { kind: "migrated" } as unknown as MigrationReport;
			},
		};
		const eraser = selectionEraser(records, undefined);
		expect(eraser.erasable).toBe(true);
		expect((await eraser.online("alice", signal)).reports).toHaveLength(1);
		expect((await eraser.window(["bob", "carol"], walk, signal)).reports).toHaveLength(2);
		expect(await eraser.migrate(walk, signal)).toHaveLength(1);
		expect(asked).toEqual([
			"erase alice true",
			"erase bob true",
			"erase carol true",
			"read subject",
		]);
	});

	it("refuses a store offering erase without migrate, or migrate without erase", () => {
		const erase = async () => ({}) as SpaceReport;
		const migrate = async () => ({}) as MigrationReport;
		expect(portsRefused(plain)).toBeUndefined();
		expect(portsRefused({ ...plain, erase, migrate })).toBeUndefined();
		expect(portsRefused({ ...plain, erase })).toContain("both, or neither");
		expect(portsRefused({ ...plain, migrate })).toContain("both, or neither");
	});
});

describe("whose a selection's record is, as the migration reads it", () => {
	const reading = selectionSubjectOf(undefined);

	it("reads format 2's own subject, for every kind", async () => {
		for (const [key, value] of [
			["c.r", stored.code(selection, "alice")],
			["p.r", stored.pin(undefined, "alice")],
			["t.tok", stored.target(target, "alice")],
			["f.fam", stored.target(target, "alice")],
		] as const) {
			expect(await reading(key, value), key).toEqual({ kind: "subject", subject: "alice" });
		}
	});

	it("reads a code's selection, a pin or a token's target 0.19 kept as unreadable, giving the one bound", async () => {
		for (const [key, value] of [
			["c.r", { format: 1, selection }],
			["p.r", { format: 1 }],
			["t.tok", { format: 1, target }],
		] as const) {
			const read = await reading(key, value);
			expect(read.kind, key).toBe("unreadable");
			const reason = read.kind === "unreadable" ? read.reason : "";
			expect(reason).toContain("86,520 s after the last 0.19 instance stopped");
			expect(reason).toContain("a 0.19 instance is still writing");
		}
	});

	it("reads a family's target 0.19 kept by its family: its subject, ended as an orphan, a failure unreadable", async () => {
		const value = { format: 1, target };
		const asked: string[] = [];
		const answering = (answer: FamilySubject) =>
			selectionSubjectOf(
				families(async () => {
					asked.push("asked");
					return answer;
				}),
			);
		expect(await answering({ kind: "subject", subject: "alice" })("f.fam", value)).toEqual({
			kind: "subject",
			subject: "alice",
		});
		expect(await answering({ kind: "ended" })("f.fam", value)).toEqual({ kind: "orphan" });
		const failing = selectionSubjectOf(
			families(async () => {
				throw new Error("a family record of another shape");
			}),
		);
		expect((await failing("f.fam", value)).kind).toBe("unreadable");
		expect(asked).toHaveLength(2);
	});

	it("reads a family's target as unreadable with no family reading composed, never as an orphan", async () => {
		const read = await reading("f.fam", { format: 1, target });
		expect(read).toMatchObject({
			kind: "unreadable",
			reason: expect.stringContaining("no reading"),
		});
	});

	it("reads a record of no kind it names, or of another shape, as unreadable", async () => {
		expect((await reading("x.other", stored.target(target, "alice"))).kind).toBe("unreadable");
		expect((await reading("t.tok", { format: 3, target })).kind).toBe("unreadable");
		expect((await reading("c.r", { format: 2, selection })).kind).toBe("unreadable");
	});
});
