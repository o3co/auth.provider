import { expect, it } from "vitest";
import { issuanceFor } from "../src/route/issuance.ts";

it("throws a session issuance's failure on, even where revoking the token fails too", async () => {
	const failing = (why: string) => async () => Promise.reject(new Error(why));
	const issued = { kind: "issued", access: { id: "a", expiresAt: 1, token: "t" } };
	const tokens = { issue: async () => issued, revokeReferenced: failing("revoking") };
	const { issue } = issuanceFor(tokens as never, "urn:test", undefined, [
		{ issued: failing("recording") },
	]);
	const grant = { subject: "s", issuedTo: "c", audience: [], scope: [] };
	await expect(issue(grant, { session: "sid" })).rejects.toThrow("recording");
});
