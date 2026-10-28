import { randomBytes } from "node:crypto";
import {
	type Deployed,
	type Instance,
	instanceOf,
	ready,
	recovered,
	sameMark,
	successes,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import { faultScene, grantsOn, on } from "../../faults/test/faults.ts";
import { boundaryCreated, boundaryOf, closingAdded, grantWritten } from "../../faults/test/wire.ts";
import type { FakeUpstream } from "../../grants/test/grants.ts";

// Each scene reads, at another instance, a grant alice established before her boundary while the
// revocation's followers are held at their first write, so her grant is not ended by its follower
// (federation-grants runs after session-lifecycle, whose first write is held): what refuses is the
// boundary, as the grant reads it. A read after the followers' cleanup proves nothing of the boundary
// and is not taken as such.

const credential = randomBytes(32).toString("base64url");
const revocations = { credential, sources: ["198.51.100.0/24"] };
const subject = "alice";

/** The ledger's revocation of alice at the instance, keeping her delegations where asked. */
async function revokeAt(i: Instance, delegations: "end" | "keep" = "end") {
	const res = await fetch(`${i.baseUrl}/ledger/subject-revocations`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			"x-forwarded-proto": "https",
			"x-forwarded-for": "198.51.100.30",
			authorization: `Bearer ${credential}`,
		},
		body: JSON.stringify({ subject, delegations }),
	});
	return {
		status: res.status,
		body: (await res.json().catch(() => ({}))) as Record<string, unknown>,
	};
}
const done = (a: { status: number; body: Record<string, unknown> }) =>
	expect([a.status, a.body.complete]).toEqual([200, true]);

/** No follower wrote, on any instance, since `from`: no session of alice's began closing, nor her grants. */
const unfollowed = (d: Deployed, from: number) => {
	for (const i of d.instances) {
		expect(successes(i, closingAdded).filter((e) => e.at > from)).toEqual([]);
	}
};

/** The control: with no fault, alice's grant established at one instance gives a token at another. */
async function grantedAt(a: Instance, b: Instance, corp: FakeUpstream) {
	const { id } = await grantsOn(a, corp).connected();
	expect((await grantsOn(b, corp).grantCall(id, "token")).status).toBe(200);
	return id;
}

/**
 * Healed: the topology has recovered, and a grant alice establishes a second and more past the
 * boundary's last write (boundaries are compared in seconds) gives a token.
 */
async function healed(d: Deployed, i: Instance, corp: FakeUpstream) {
	await recovered(d);
	await ready(i);
	const written = d.instances.flatMap((x) => successes(x, boundaryOf(subject)).map((e) => e.at));
	const after = Math.max(...written) + 1_100 - performance.now();
	if (after > 0) await new Promise((resolve) => setTimeout(resolve, after));
	const g = grantsOn(i, corp);
	const { id } = await g.connected();
	expect((await g.grantCall(id, "token")).status).toBe(200);
}

describe("a subject's boundary refusing, from any instance, a federation grant established before it", () => {
	it("gives no token, at another instance, from a grant established before a boundary whose followers are still to run [guarantee-4-c] {fault:H2}", async () => {
		await on(
			{
				name: "federation-revocation-boundary-h2",
				scene: (c) => faultScene(c, revocations),
				instances: 2,
			},
			async (d, corp) => {
				const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
				const id = await grantedAt(a, b, corp);
				const bobs = String((await grantsOn(a, corp).lodge({ sub: "bob" })).body.grant_id);
				const from = performance.now();
				const following = a.relay.hold(closingAdded);
				const asked = revokeAt(a);
				// The followers begin only once the boundary's write is confirmed.
				const held = await following;
				expect(successes(a, boundaryOf(subject)).filter((e) => e.at > from).length).toBeGreaterThan(
					0,
				);
				unfollowed(d, from);
				// Ended as read: the grant, asked for a token, is judged by her boundary and written revoked
				// there (`backstop`), at B; her grants' own follower runs after session-lifecycle's, held.
				const reading = performance.now();
				const token = await grantsOn(b, corp).grantCall(id, "token");
				expect([token.status, token.body.error, token.body.error_description]).toEqual([
					410,
					"grant_revoked",
					"backstop",
				]);
				expect(successes(b, grantWritten).some((e) => e.at > reading)).toBe(true);
				// Another subject's intent is untouched.
				const his = await grantsOn(b, corp).grantCall(bobs, "status", { sub: "bob" });
				expect(his.body.status).toBe("pending");
				held.release();
				done(await asked);
				await healed(d, b, corp);
			},
		);
	});

	it("creates one boundary for alice whom two instances revoke at once, both answering done, and gives no token at a third from a grant established before it [guarantee-4-c] {fault:H2}", async () => {
		await on(
			{
				name: "federation-revocation-boundary-h2-together",
				scene: (c) => faultScene(c, revocations),
				instances: 3,
			},
			async (d, corp) => {
				const [a, b, c] = [instanceOf(d, 0), instanceOf(d, 1), instanceOf(d, 2)];
				const id = await grantedAt(c, a, corp);
				const from = performance.now();
				// Both have found no boundary and are about to create one; each then holds its followers.
				const creating = [
					a.relay.hold(boundaryCreated(subject)),
					b.relay.hold(boundaryCreated(subject)),
				];
				const following = [a.relay.hold(closingAdded), b.relay.hold(closingAdded)];
				const asked = [revokeAt(a), revokeAt(b)];
				for (const held of await Promise.all(creating)) held.release();
				const followers = await Promise.all(following);
				// One created it; the other found it held and wrote it from that. A write held past the
				// command timeout is resent under its mark and answered again, so creations are counted by mark.
				const created = [a, b].flatMap((i) =>
					successes(i, boundaryCreated(subject)).filter((e) => e.at > from),
				);
				const marks = created.filter(
					(e, n) => created.findIndex((f) => sameMark(f.command, e.command)) === n,
				);
				expect(created.length).toBeGreaterThan(0);
				expect(marks).toHaveLength(1);
				unfollowed(d, from);
				const reading = performance.now();
				const token = await grantsOn(c, corp).grantCall(id, "token");
				expect([token.status, token.body.error, token.body.error_description]).toEqual([
					410,
					"grant_revoked",
					"backstop",
				]);
				expect(successes(c, grantWritten).some((e) => e.at > reading)).toBe(true);
				for (const held of followers) held.release();
				for (const answer of await Promise.all(asked)) done(answer);
				await healed(d, c, corp);
			},
		);
	});

	it("gives a token, at another instance, from a grant established before a revocation that keeps delegations, where grants keep on subject revocation [guarantee-4-c] {fault:H2}", async () => {
		await on(
			{
				name: "federation-revocation-boundary-h2-keep",
				scene: (c) => faultScene(c, revocations, { keepOnSubjectRevocation: true }),
				instances: 2,
			},
			async (d, corp) => {
				const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
				const id = await grantedAt(a, b, corp);
				const from = performance.now();
				const following = a.relay.hold(closingAdded);
				const asked = revokeAt(a, "keep");
				const held = await following;
				// Her sessions' boundary moved; her delegations' did not, and the grant answers to that alone.
				expect(successes(a, boundaryOf(subject)).filter((e) => e.at > from).length).toBeGreaterThan(
					0,
				);
				unfollowed(d, from);
				expect((await grantsOn(b, corp).grantCall(id, "token")).status).toBe(200);
				held.release();
				done(await asked);
				// Once its followers ran too, the grant still answers.
				expect((await grantsOn(b, corp).grantCall(id, "token")).status).toBe(200);
			},
		);
	});
});
