import { expect, it } from "vitest";
import { DestinationRefused } from "../src/contract.ts";

it("tells a destination refusal by its mark, so one from another copy of outbound-policy is told too", () => {
	expect(DestinationRefused.is(new DestinationRefused("scheme"))).toBe(true);
	// What a second bundled copy throws: another class, the same mark.
	const fromAnotherCopy = Object.assign(new Error("outbound destination refused: denied"), {
		[Symbol.for("@mod/outbound-policy.destination-refused")]: true,
		reason: "denied",
	});
	expect(DestinationRefused.is(fromAnotherCopy)).toBe(true);
});

it("tells no other error, nor anything that is no object", () => {
	for (const error of [
		new Error("outbound destination refused: denied"),
		Object.assign(new Error("x"), {
			[Symbol.for("@mod/outbound-policy.destination-refused")]: "yes",
		}),
		{ reason: "denied" },
		undefined,
		null,
		"denied",
	]) {
		expect(DestinationRefused.is(error), String(error)).toBe(false);
	}
});
