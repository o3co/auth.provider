import { expect, it } from "vitest";
import {
	type Eraser,
	erasers,
	erasureMarks,
	type SpaceReport,
	type SubjectOf,
	type SubjectReading,
} from "../src/contract.ts";

it("keys erasers by their name, the one a space's erasedBy gives", () => {
	const eraser = { name: "users" } as Eraser;
	expect(erasers.rule).toMatchObject({ multiplicity: "keyed" });
	expect((erasers.rule as { keyOf: (e: Eraser) => string }).keyOf(eraser)).toBe("users");
});

it("names erasure's marks under its own name, frozen", () => {
	expect(erasureMarks).toEqual({
		enabled: "account-erasure.enabled",
		journal: "account-erasure.journal",
	});
	expect(Object.isFrozen(erasureMarks)).toBe(true);
});

it("takes no plain object for a report: one is made by records, behind a cast", () => {
	// @ts-expect-error A report's brand is records' to give.
	const forged: SpaceReport = { kind: "erased", space: "users-store.links", removed: 1 };
	expect(forged.kind).toBe("erased");
});

it("states whether an eraser can erase, and which erasers it follows", () => {
	const empty = { reports: [], logoutGaps: 0 };
	const eraser: Eraser = {
		name: "mfa-flows",
		erasable: false,
		after: ["mfa"],
		online: async () => empty,
		window: async () => empty,
		migrate: async () => [],
	};
	expect(eraser.erasable).toBe(false);
	// @ts-expect-error Whether it can erase is stated, never left out, in 0.20.
	const unstated: Eraser = { ...eraser, erasable: undefined };
	expect(unstated.after).toEqual(["mfa"]);
});

it("reads a record's subject three ways, an unreadable one with why", async () => {
	const reading: SubjectReading = async (key) =>
		key === "a" ? { kind: "subject", subject: "alice" } : { kind: "unreadable", reason: "sealed" };
	expect(await reading("a", {})).toEqual({ kind: "subject", subject: "alice" });
	// @ts-expect-error An unreadable record says why: it stops its space, proving nothing.
	const silent: SubjectOf = { kind: "unreadable" };
	expect(silent.kind).toBe("unreadable");
});
