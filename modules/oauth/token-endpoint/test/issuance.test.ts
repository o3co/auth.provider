import { expect, it } from "vitest";
import { bundleOf, issuanceFor } from "../src/route/issuance.ts";

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

it("notes the subject it hands tokens, reading the grant once", async () => {
	const signed: string[] = [];
	const tokens = {
		issue: async ({ grant }: { grant: { subject: string } }) => {
			signed.push(grant.subject);
			return { kind: "issued", access: { id: "a", expiresAt: 1, token: "t" } };
		},
	};
	const bundle = bundleOf();
	const { issue } = issuanceFor(tokens as never, "urn:test", undefined, [], bundle);
	let reads = 0;
	const grant = Object.defineProperty({ issuedTo: "c", audience: [], scope: [] }, "subject", {
		enumerable: true,
		get: () => (++reads === 1 ? "bob" : "alice"),
	}) as unknown as { subject: string; issuedTo: string; audience: string[]; scope: string[] };
	await issue(grant);
	expect(reads).toBe(1);
	expect(signed).toEqual(["bob"]);
	expect([...bundle.subjects]).toEqual(["bob"]);
});
