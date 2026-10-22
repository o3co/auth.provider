import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { witnessAt } from "../src/witness.ts";

/** What a second bundled copy of outbound-policy throws: another class, its mark. */
const refusedByAnotherCopy = () =>
	Object.assign(new Error("outbound destination refused: denied"), {
		[Symbol.for("@mod/outbound-policy.destination-refused")]: true,
		reason: "denied",
	});

it("logs a refusal a second copy of outbound-policy throws by its reason, not as no answer", async () => {
	const warned: unknown[] = [];
	const witness = witnessAt({
		urls: {
			read: "https://w.example/r",
			enroll: "https://w.example/e",
			withdraw: "https://w.example/w",
			clear: "https://w.example/c",
		},
		out: {
			fetch: async () => {
				throw refusedByAnotherCopy();
			},
		},
		credential: "Bearer test",
		narrower: {},
		heldMs: 1000,
		now: () => 0,
		warn: (event, fields) => void warned.push([event, fields]),
	});
	await expect(witness.read("alice")).rejects.toSatisfy(isUnavailable);
	expect(warned).toEqual([
		["passkey-witness-http.ledger_failed", { call: "read", reason: "denied" }],
	]);
});
