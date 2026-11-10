import { expect, it } from "vitest";
import { type Eraser, erasers, erasureMarks, type SpaceReport } from "../src/contract.ts";

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
