import { isUnavailable } from "@mod/kernel";
import { configuredUrl } from "@mod/url-setting/testing";
import { expect, it } from "vitest";
import { calls } from "../src/calls/calls.ts";

/** What a second bundled copy of outbound throws: another class, outbound's mark. */
const fromAnotherCopy = () =>
	Object.assign(new Error("outbound unavailable"), {
		[Symbol.for("@mod/outbound.unavailable")]: true,
		failure: "busy",
	});

it("logs the failure a second copy of outbound throws by its kind, not as no answer", async () => {
	const warned: unknown[] = [];
	const ledger = calls({
		out: {
			fetch: async () => {
				throw fromAnotherCopy();
			},
		},
		credential: undefined,
		narrowerOf: () => ({}),
		warn: (event, fields) => void warned.push([event, fields]),
	});
	await expect(
		ledger.verify(configuredUrl("https://users.example/v"), "alice", "pw"),
	).rejects.toSatisfy(isUnavailable);
	expect(warned).toEqual([["users-http.ledger_failed", { reason: "busy" }]]);
});
