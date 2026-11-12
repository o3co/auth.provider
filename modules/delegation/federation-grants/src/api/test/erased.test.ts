import { revocations, subjectErasure } from "@mod/subject-revocation";
import { expect, it, vi } from "vitest";
import { harness, said } from "../../../test/harness.ts";

it("refuses a lodging for a subject erased here as unknown, keeping nothing and auditing it without the subject", async () => {
	const h = await harness();
	h.stores.erased.add("gone");
	const lodged = await h.lodge({ sub: "gone" });
	expect(said(lodged)).toBe("403 access_denied subject_unknown");
	const denied = h.events.filter((e) => e.kind === "federation.grant.request.denied");
	expect(denied.map((e) => [e.subject, e.attributes])).toEqual([
		[
			undefined,
			{ client: "worker", outcome: "subject_unknown", withheld: "erased", source: "127.0.0.1" },
		],
	]);
	expect(h.events.some((e) => e.kind === "federation.grant.requested")).toBe(false);
});

it("hands no token for a subject erased once the grant was judged, answered as a grant its revocation ended, recording no success", async () => {
	const h = await harness();
	const { id } = await h.connected();
	const kept = h.app.get(revocations);
	const compare = kept.compare.bind(kept);
	// The route reads the boundary twice, the grant's judging and the token's: the subject is erased
	// just after the second, the last before the fence.
	let read = 0;
	vi.spyOn(kept, "compare").mockImplementation(async (...args) => {
		const answer = await compare(...args);
		if (++read === 2) await h.app.get(subjectErasure).markErased("alice");
		return answer;
	});
	expect(said(await h.grantCall(id, "token"))).toBe("410 grant_revoked backstop");
	expect(read).toBe(2);
	expect(h.events.some((e) => e.kind === "federation.grant.token.success")).toBe(false);
	// Audited once, as every refused token request is, naming no erased subject.
	const denied = h.events.filter((e) => e.kind === "federation.grant.token.denied");
	expect(denied.map((e) => [e.subject, e.attributes?.reason, e.attributes?.withheld])).toEqual([
		[undefined, "backstop", "erased"],
	]);
});

it("audits a token, a renewal and a revocation of an erased subject's grant without the subject, held or not", async () => {
	for (const tombstone of [false, true]) {
		const h = await harness();
		const { id } = await h.connected();
		await h.app.get(subjectErasure).markErased("alice");
		const marked = h.events.length;
		// With its tombstone and no eraser run yet (one aborted), the grant is held and answered revoked.
		if (tombstone) h.stores.erased.add("alice");
		expect(said(await h.grantCall(id, "token"))).toBe("410 grant_revoked backstop");
		expect((await h.grantCall(id, "revoke")).status).toBe(204);
		// Since the mark nothing names the subject: every event about it says why it is withheld.
		const since = h.events.slice(marked);
		expect(
			since.map((e) => [e.kind, e.subject, e.attributes?.withheld]),
			String(tombstone),
		).toEqual([
			...(tombstone ? [] : [["federation.grant.revoked", undefined, "erased"]]),
			["federation.grant.token.denied", undefined, "erased"],
		]);
	}
});
