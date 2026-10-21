import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { keysAt } from "../src/lookup.ts";

/** What a second bundled copy of outbound-policy throws: another class, its mark. */
const refusedByAnotherCopy = () =>
	Object.assign(new Error("outbound destination refused: denied"), {
		[Symbol.for("@mod/outbound-policy.destination-refused")]: true,
		reason: "denied",
	});

it("logs a refusal a second copy of outbound-policy throws by its reason, not as no answer", async () => {
	const warned: unknown[] = [];
	const keys = keysAt({
		issuer: "https://issuer.example",
		url: "https://keys.example/k",
		out: {
			fetch: async () => {
				throw refusedByAnotherCopy();
			},
		},
		credential: undefined,
		narrower: {},
		warn: (event, fields) => void warned.push([event, fields]),
	});
	await expect(keys.keysOf({ subject: "dev-1" })).rejects.toSatisfy(isUnavailable);
	expect(warned).toEqual([["signer-keys-http.ledger_failed", { reason: "denied" }]]);
});
