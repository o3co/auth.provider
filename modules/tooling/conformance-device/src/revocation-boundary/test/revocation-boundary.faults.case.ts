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
import {
	type Answer,
	alice,
	approvedAt,
	type Device,
	faultScene,
	on,
	pollAt,
	said,
} from "../../faults/test/faults.ts";
import { boundaryCreated, boundaryOf, closingAdded, takeOf } from "../../faults/test/wire.ts";

// Each scene reads, at another instance, a device code alice approved before her boundary while the
// revocation's followers are held at their first write, so her sessions are not closed: what refuses
// is the boundary alone. In this composition the only follower is session-lifecycle (no
// federation-grants nor mfa-flows is composed), whose first write is adding her sessions to its
// closings. A read after the followers' cleanup proves nothing of the boundary and is not taken as such.

const credential = randomBytes(32).toString("base64url");
const subject = "user-alice";
const scene = faultScene({
	users: [{ ...alice, subject }],
	revocations: { credential, sources: ["198.51.100.0/24"] },
});

/** The ledger's revocation of alice at the instance, from its block over https, as its proxy forwards it. */
async function revokeAt(i: Instance): Promise<Answer> {
	const res = await fetch(`${i.baseUrl}/ledger/subject-revocations`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			"x-forwarded-proto": "https",
			"x-forwarded-for": "198.51.100.30",
			authorization: `Bearer ${credential}`,
		},
		body: JSON.stringify({ subject }),
	});
	const text = await res.text();
	let body: Record<string, unknown> = {};
	try {
		body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
	} catch {}
	return { status: res.status, body };
}
const done = (a: Answer) => expect([a.status, a.body.complete]).toEqual([200, true]);

/**
 * The device approved before the boundary gives no token at the instance: `invalid_grant`, the
 * approving session's entry refused by the subject's boundary before the poll takes the approval, so
 * the take is never written; the session is not closed, the followers held, so what refuses is the
 * boundary.
 */
async function refusedAt(i: Instance, d: Device) {
	expect(said(await pollAt(i, d))).toEqual([400, "invalid_grant"]);
	expect(successes(i, takeOf(d))).toEqual([]);
}

/** No follower wrote, on any instance, since `from`: no session of alice's began closing. */
const unfollowed = (d: Deployed, from: number) => {
	for (const i of d.instances) {
		expect(successes(i, closingAdded).filter((e) => e.at > from)).toEqual([]);
	}
};

/** The control: with no fault, a device alice approves at one instance is polled for a token at another. */
async function control(d: Deployed) {
	const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
	expect(said(await pollAt(b, await approvedAt(a)))).toEqual([200, "Bearer"]);
}

/** Healed: the topology has recovered, and a device alice approves after her boundary, from a new login, gives a token. */
async function healed(d: Deployed, i: Instance) {
	await recovered(d);
	await ready(i);
	// A boundary is compared in seconds: a login within its second is revoked too, so the new one comes
	// a second and more after the boundary's last write.
	const written = d.instances.flatMap((x) => successes(x, boundaryOf(subject)).map((e) => e.at));
	const after = Math.max(...written) + 1_100 - performance.now();
	if (after > 0) await new Promise((resolve) => setTimeout(resolve, after));
	expect(said(await pollAt(i, await approvedAt(i)))).toEqual([200, "Bearer"]);
}

describe("a subject's boundary refusing, from any instance, a device code approved before it", () => {
	it("gives no token, at another instance, for a device approved before a boundary whose followers are still to run [guarantee-4-b] {fault:H2}", async () => {
		await on({ name: "device-revocation-boundary-h2", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(d);
			const device = await approvedAt(a);
			const from = performance.now();
			const following = a.relay.hold(closingAdded);
			const asked = revokeAt(a);
			// The followers begin only once the boundary's write is confirmed.
			const held = await following;
			expect(successes(a, boundaryOf(subject)).filter((e) => e.at > from).length).toBeGreaterThan(
				0,
			);
			unfollowed(d, from);
			await refusedAt(b, device);
			held.release();
			done(await asked);
			await healed(d, b);
		});
	});

	it("creates one boundary for alice whom two instances revoke at once, both answering done, and gives no token at a third for a device approved before it [guarantee-4-b] {fault:H2}", async () => {
		await on({ name: "device-revocation-boundary-h2-together", scene, instances: 3 }, async (d) => {
			const [a, b, c] = [instanceOf(d, 0), instanceOf(d, 1), instanceOf(d, 2)];
			await control(d);
			const device = await approvedAt(c);
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
			await refusedAt(c, device);
			for (const held of followers) held.release();
			for (const answer of await Promise.all(asked)) done(answer);
			await healed(d, c);
		});
	});
});
