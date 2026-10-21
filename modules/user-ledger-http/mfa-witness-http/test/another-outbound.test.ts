import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { witnessAt } from "../src/witness.ts";

/** What a second bundled copy of outbound throws: another class, outbound's mark. */
const fromAnotherCopy = () =>
	Object.assign(new Error("outbound unavailable"), {
		[Symbol.for("@mod/outbound.unavailable")]: true,
		failure: "busy",
	});

it("logs the failure a second copy of outbound throws by its kind, not as no answer", async () => {
	const warned: unknown[] = [];
	const witness = witnessAt({
		urls: {
			read: "https://w.example/r",
			enroll: "https://w.example/e",
			clear: "https://w.example/c",
		},
		out: {
			fetch: async () => {
				throw fromAnotherCopy();
			},
		},
		credential: "Bearer test",
		narrower: {},
		heldMs: 1000,
		now: () => 0,
		warn: (event, fields) => void warned.push([event, fields]),
	});
	await expect(witness.read("alice")).rejects.toSatisfy(isUnavailable);
	expect(warned).toEqual([["mfa-witness-http.ledger_failed", { call: "read", reason: "busy" }]]);
});
