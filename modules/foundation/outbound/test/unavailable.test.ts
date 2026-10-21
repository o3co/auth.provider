import { Unavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { isOutboundUnavailable, OutboundUnavailable } from "../src/contract.ts";

it("tells outbound's no usable answer by its mark, so one from another copy of outbound is told too", () => {
	expect(isOutboundUnavailable(new OutboundUnavailable("timeout"))).toBe(true);
	// What a second bundled copy of outbound throws: another class, the same mark.
	const fromAnotherCopy = Object.assign(new Error("outbound unavailable"), {
		[Symbol.for("@mod/outbound.unavailable")]: true,
		failure: "busy",
	});
	expect(isOutboundUnavailable(fromAnotherCopy)).toBe(true);
});

it("tells no other error, another unavailable included, nor anything that is no object", () => {
	for (const error of [
		new Unavailable("outbound"),
		new Error("outbound unavailable"),
		Object.assign(new Error("x"), { [Symbol.for("@mod/outbound.unavailable")]: "yes" }),
		{ failure: "busy" },
		undefined,
		null,
		"outbound unavailable",
	]) {
		expect(isOutboundUnavailable(error), String(error)).toBe(false);
	}
});
