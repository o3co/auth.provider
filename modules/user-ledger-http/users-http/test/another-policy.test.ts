import { isUnavailable } from "@mod/kernel";
import { configuredUrl } from "@mod/url-setting/testing";
import { expect, it } from "vitest";
import { calls } from "../src/calls/calls.ts";

/** What a second bundled copy of outbound-policy throws: another class, its mark. */
const refusedByAnotherCopy = () =>
	Object.assign(new Error("outbound destination refused: denied"), {
		[Symbol.for("@mod/outbound-policy.destination-refused")]: true,
		reason: "denied",
	});

it("logs a refusal a second copy of outbound-policy throws by its reason, not as no answer", async () => {
	const warned: unknown[] = [];
	const ledger = calls({
		out: {
			fetch: async () => {
				throw refusedByAnotherCopy();
			},
		},
		credential: undefined,
		narrowerOf: () => ({}),
		warn: (event, fields) => void warned.push([event, fields]),
	});
	await expect(
		ledger.verify(configuredUrl("https://users.example/v"), "alice", "pw"),
	).rejects.toSatisfy(isUnavailable);
	expect(warned).toEqual([["users-http.ledger_failed", { reason: "denied" }]]);
});
