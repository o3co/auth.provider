import { expect, it } from "vitest";
import { isLabel } from "../src/contract.ts";

it("accepts as a label 1 to 64 characters, well formed, with no line break, control or bidirectional control", () => {
	const fits = [
		"phone",
		"a".repeat(64),
		"\u{1f511}".repeat(64),
		" ~\u00a0\u061b\u061d\u200d\u2010\u2027\u202f\u2065\u206a",
	];
	expect(fits.filter((label) => !isLabel(label))).toEqual([]);
	const refused = ["", "a".repeat(65), "\u{1f511}".repeat(65), "\ud800", "x\udc00"];
	const breaking = ["\u0000", "\n", "\u001f", "\u007f", "\u009f", "\u2028", "\u2029"];
	const reordering = ["\u061c", "\u200e", "\u200f", "\u202a", "\u202e", "\u2066", "\u2069"];
	const marked = [...breaking, ...reordering].map((c) => `desk${c}top`);
	expect([...refused, ...marked].filter((label) => isLabel(label))).toEqual([]);
});
