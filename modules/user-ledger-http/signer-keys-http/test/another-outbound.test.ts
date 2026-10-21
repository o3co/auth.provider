import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { keysAt } from "../src/lookup.ts";

/** What a second bundled copy of outbound throws: another class, outbound's mark. */
const fromAnotherCopy = () =>
	Object.assign(new Error("outbound unavailable"), {
		[Symbol.for("@mod/outbound.unavailable")]: true,
		failure: "busy",
	});

it("logs the failure a second copy of outbound throws by its kind, not as no answer", async () => {
	const warned: unknown[] = [];
	const keys = keysAt({
		issuer: "https://issuer.example",
		url: "https://keys.example/k",
		out: {
			fetch: async () => {
				throw fromAnotherCopy();
			},
		},
		credential: undefined,
		narrower: {},
		warn: (event, fields) => void warned.push([event, fields]),
	});
	await expect(keys.keysOf({ subject: "dev-1" })).rejects.toSatisfy(isUnavailable);
	expect(warned).toEqual([["signer-keys-http.ledger_failed", { reason: "busy" }]]);
});
