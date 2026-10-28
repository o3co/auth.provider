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
	accessAt,
	exchangeAt,
	faultScene,
	on,
	said,
	users,
} from "../../faults/test/faults.ts";
import { boundaryCreated, boundaryOf, closingAdded } from "../../faults/test/wire.ts";

// Each scene exchanges, at another instance, an access token alice was given before her boundary while
// the revocation's followers are held at their first write, so her session is not closed nor its
// tokens revoked: what refuses is the boundary alone. In this composition the only follower is
// session-lifecycle (no federation-grants nor mfa-flows is composed), whose first write is adding her
// sessions to its closings. A read after the followers' cleanup proves nothing of the boundary and is
// not taken as such.

const credential = randomBytes(32).toString("base64url");
const scene = faultScene({ revocations: { credential, sources: ["198.51.100.0/24"] } });

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
		body: JSON.stringify({ subject: users.alice.subject }),
	});
	const text = await res.text();
	let body: Record<string, unknown> = {};
	try {
		body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
	} catch {}
	return { status: res.status, body };
}
const done = (a: Answer) => expect([a.status, a.body.complete]).toEqual([200, true]);

/** The token alice was given before the boundary is exchanged for none at the instance, refused as revoked. */
async function refusedAt(i: Instance, token: string) {
	const answer = await exchangeAt(i, token);
	expect(said(answer)).toEqual([400, "invalid_request"]);
	expect(answer.body.access_token).toBeUndefined();
	// The subject token's own check failed: a session closed, or a family ended, is told apart in the
	// description (token-exchange), and her session is not closed, the followers held; the token is
	// hours from its expiry.
	expect(answer.body.error_description).toBe("subject_token validation failed");
}

/** No follower wrote, on any instance, since `from`: no session of alice's began closing. */
const unfollowed = (d: Deployed, from: number) => {
	for (const i of d.instances) {
		expect(successes(i, closingAdded).filter((e) => e.at > from)).toEqual([]);
	}
};

/** The control: with no fault, a token given at one instance is exchanged at another. */
async function control(d: Deployed) {
	const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
	expect(said(await exchangeAt(b, await accessAt(a, users.bob)))).toEqual([200, "Bearer"]);
}

/**
 * Healed: the topology has recovered, and a token alice is given from a login a second and more past the
 * boundary's last write (boundaries are compared in seconds) is exchanged.
 */
async function healed(d: Deployed, i: Instance) {
	await recovered(d);
	await ready(i);
	const written = d.instances.flatMap((x) =>
		successes(x, boundaryOf(users.alice.subject)).map((e) => e.at),
	);
	const after = Math.max(...written) + 1_100 - performance.now();
	if (after > 0) await new Promise((resolve) => setTimeout(resolve, after));
	expect(said(await exchangeAt(i, await accessAt(i, users.alice)))).toEqual([200, "Bearer"]);
}

describe("a subject's boundary refusing, from any instance, a token exchange of a token given before it", () => {
	it("exchanges, at another instance, no token given before a boundary whose followers are still to run [guarantee-4-e] {fault:H2}", async () => {
		await on({ name: "exchange-revocation-boundary-h2", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(d);
			const [hers, his] = [await accessAt(a, users.alice), await accessAt(a, users.bob)];
			const from = performance.now();
			const following = a.relay.hold(closingAdded);
			const asked = revokeAt(a);
			// The followers begin only once the boundary's write is confirmed.
			const held = await following;
			expect(
				successes(a, boundaryOf(users.alice.subject)).filter((e) => e.at > from).length,
			).toBeGreaterThan(0);
			unfollowed(d, from);
			await refusedAt(b, hers);
			// Another user's token is untouched.
			expect(said(await exchangeAt(b, his))).toEqual([200, "Bearer"]);
			held.release();
			done(await asked);
			await healed(d, b);
		});
	});

	it("creates one boundary for alice whom two instances revoke at once, both answering done, and exchanges at a third no token given before it [guarantee-4-e] {fault:H2}", async () => {
		await on(
			{ name: "exchange-revocation-boundary-h2-together", scene, instances: 3 },
			async (d) => {
				const [a, b, c] = [instanceOf(d, 0), instanceOf(d, 1), instanceOf(d, 2)];
				await control(d);
				const hers = await accessAt(c, users.alice);
				const from = performance.now();
				// Both have found no boundary and are about to create one; each then holds its followers.
				const subject = users.alice.subject;
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
				await refusedAt(c, hers);
				for (const held of followers) held.release();
				for (const answer of await Promise.all(asked)) done(answer);
				await healed(d, c);
			},
		);
	});
});
