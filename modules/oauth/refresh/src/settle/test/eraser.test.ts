import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { describe, expect, it } from "vitest";
import type { FamilyStore } from "../../store.ts";
import { familyEraser, familySubjectOf, familySubjectsIn } from "../eraser.ts";

const signal = new AbortController().signal;
const walk: Walk = { sweep: async () => ({ keys: [], server: "one" }) };
const plain = {
	save: async () => "created" as const,
	read: async () => undefined,
	update: async () => undefined,
};
const erased = { kind: "erased", space: "families", removed: 1 } as unknown as SpaceReport;
const family = {
	format: 2,
	current: "h",
	clientId: "app",
	subject: "alice",
	scope: [],
	audience: [],
	authenticatedAt: 0,
	amr: [],
	expiresAt: 1,
};

describe("refresh's eraser", () => {
	it("reads a family's subject from it, a revoked mark as an orphan, and anything else as unreadable", async () => {
		expect(await familySubjectOf("f", family)).toEqual({ kind: "subject", subject: "alice" });
		expect(await familySubjectOf("f", { format: 1, revoked: true })).toEqual({ kind: "orphan" });
		for (const value of [
			{ format: 1, revoked: true, subject: "alice" },
			null,
			{ ...family, extra: 1 },
		]) {
			expect((await familySubjectOf("f", value)).kind).toBe("unreadable");
		}
	});

	it("states that it cannot erase where the store offers none of its ports, answering empty reports", async () => {
		const eraser = familyEraser(plain as unknown as FamilyStore);
		expect([eraser.name, eraser.erasable]).toEqual(["refresh", false]);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.migrate(walk, signal)).toEqual([]);
	});

	it("passes on the store's report, each subject in a window, and migrates by the family's reading", async () => {
		const asked: string[] = [];
		const families = {
			...plain,
			erase: async (subject: string) => {
				asked.push(subject);
				return erased;
			},
			migrate: async (_walk: Walk, reading: SubjectReading) => {
				asked.push((await reading("f", family)).kind);
				return { kind: "migrated", space: "families", indexed: 1, removed: 0 } as MigrationReport;
			},
			unowned: async () => "closed" as const,
		};
		const eraser = familyEraser(families as unknown as FamilyStore);
		expect(eraser.erasable).toBe(true);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [erased], logoutGaps: 0 });
		expect((await eraser.window(["bob", "carol"], walk, signal)).reports).toEqual([erased, erased]);
		expect(await eraser.migrate(walk, signal)).toHaveLength(1);
		expect(asked).toEqual(["alice", "bob", "carol", "subject"]);
	});
});

describe("whose a family is, for claims-selection", () => {
	/** A family store answering each family from `held` through a change writing nothing; its read is never asked. */
	const answering = (held: Record<string, unknown>, asked: string[] = []) =>
		familySubjectsIn({
			...plain,
			read: async () => {
				throw new Error("a plain read is never asked");
			},
			update: async (id: string, change: (record: never) => unknown) => {
				const before = held[id];
				if (before === undefined) return undefined;
				asked.push(
					`update ${id} ${change(before as never) === undefined ? "writing nothing" : "writing"}`,
				);
				return { before, after: before };
			},
		} as unknown as FamilyStore);

	it("answers a family's subject from one confirmed change writing nothing", async () => {
		const asked: string[] = [];
		expect(await answering({ f: family }, asked).subjectOf("f")).toEqual({
			kind: "subject",
			subject: "alice",
		});
		expect(asked).toEqual(["update f writing nothing"]);
	});

	it("answers ended for no record, or a revoked mark", async () => {
		const families = answering({ marked: { format: 1, revoked: true } });
		expect(await families.subjectOf("gone")).toEqual({ kind: "ended" });
		expect(await families.subjectOf("marked")).toEqual({ kind: "ended" });
	});

	it("throws for a record it cannot read, and for a store that cannot tell, never answering ended", async () => {
		await expect(answering({ f: { ...family, extra: 1 } }).subjectOf("f")).rejects.toThrow(
			"a family's record of another shape",
		);
		const failing = familySubjectsIn({
			...plain,
			update: async () => {
				throw new Error("unavailable");
			},
		} as unknown as FamilyStore);
		await expect(failing.subjectOf("f")).rejects.toThrow();
	});
});
