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
import {
	boundariesPut,
	boundaryCreated,
	boundaryOf,
	closingAdded,
	grantWritten,
} from "../../faults/test/wire.ts";
import type { FakeUpstream } from "../../grants/test/grants.ts";

// Each scene reads, at another instance, a grant alice established before her boundary while the
// revocation's followers are held at their first write, so her grant is not ended by its follower: what
// refuses is the boundary, as the grant reads it. Followers run one at a time in the composition's order
// (subject-revocation's followers.ts), federation-grants' after session-lifecycle's, whose first write is
// held; were they reordered, the revoking instance would write the grant before the read, which the
// scenes check it does not. A read after the followers' cleanup proves nothing of the boundary and is
// not taken as such.

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

/** No grant was written on the revoking instances since `from`: her grants' follower has not run. */
const grantsUnfollowed = (revoking: readonly Instance[], from: number) => {
	for (const i of revoking)
		expect(successes(i, grantWritten).filter((e) => e.at > from)).toEqual([]);
};

/**
 * Refused at the instance as read: `410` `grant_revoked`, the grant written revoked there, by this read,
 * judged by her boundary. The description (`backstop`) is shared with the follower and the sweep; the
 * write at the reading instance is what tells this read.
 */
async function endedAsRead(i: Instance, corp: FakeUpstream, id: string) {
	const reading = performance.now();
	const token = await grantsOn(i, corp).grantCall(id, "token");
	expect([token.status, token.body.error, token.body.error_description]).toEqual([
		410,
		"grant_revoked",
		"backstop",
	]);
	expect(successes(i, grantWritten).some((e) => e.at > reading)).toBe(true);
}

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
				grantsUnfollowed([a], from);
				await endedAsRead(b, corp, id);
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
				grantsUnfollowed([a, b], from);
				await endedAsRead(c, corp, id);
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
				// Her sessions' boundary moved; her delegations' did not (she held none), and the grant answers
				// to that alone.
				const written = successes(a, boundaryOf(subject)).filter((e) => e.at > from);
				expect(written.length).toBeGreaterThan(0);
				for (const w of written) {
					expect(typeof boundariesPut(w.command).sessions).toBe("number");
					expect(boundariesPut(w.command).delegations).toBeUndefined();
				}
				unfollowed(d, from);
				expect((await grantsOn(b, corp).grantCall(id, "token")).status).toBe(200);
				held.release();
				done(await asked);
				// Once its followers ran too, the grant still answers.
				expect((await grantsOn(b, corp).grantCall(id, "token")).status).toBe(200);
				// A later revocation that ends delegations moves that boundary too, and the grant, read at B
				// while that revocation's followers are held, is refused by it. She logs in again first, a
				// second and more past the boundary, so that revocation's followers have a session to close.
				const keptAt = Math.max(...written.map((w) => w.at));
				const wait = keptAt + 1_100 - performance.now();
				if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
				await grantsOn(a, corp).loggedIn();
				const ending = performance.now();
				const followingEnd = a.relay.hold(closingAdded);
				const askedEnd = revokeAt(a, "end");
				const heldEnd = await followingEnd;
				const moved = successes(a, boundaryOf(subject)).filter((e) => e.at > ending);
				expect(moved.some((w) => typeof boundariesPut(w.command).delegations === "number")).toBe(
					true,
				);
				grantsUnfollowed([a], ending);
				await endedAsRead(b, corp, id);
				heldEnd.release();
				done(await askedEnd);
				// A grant she establishes after that boundary, a second and more past it, answers.
				const endedAt = Math.max(...moved.map((w) => w.at));
				const later = endedAt + 1_100 - performance.now();
				if (later > 0) await new Promise((resolve) => setTimeout(resolve, later));
				const fresh = await grantsOn(a, corp).connected();
				expect((await grantsOn(b, corp).grantCall(fresh.id, "token")).status).toBe(200);
			},
		);
	});
});
