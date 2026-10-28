import { randomBytes } from "node:crypto";
import {
	confirmation,
	type Deployed,
	type Instance,
	instanceOf,
	ready,
	reconnected,
	recovered,
	replicasOnline,
	repointed,
	runIdOf,
	successes,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import { faultScene, loginAt, nextSource, on, said } from "../../faults/test/faults.ts";
import { boundaryOf, closingAdded, sessionClosed } from "../../faults/test/wire.ts";

// The ledger's route uses the store in three steps: its request window's count, the subject's
// boundary, and the followers (session-lifecycle adding the subject's sessions to its closings first).
// Each unavailable answer names the step it stopped at: no `state` (the window could not count),
// `unknown` (the boundary's write not confirmed), `incomplete` (written, a follower not finished).
// Done (`200 complete`) is answered only where every step's dependency answered.

const credential = randomBytes(32).toString("base64url");
const users = {
	alice: { username: "alice", password: "alice-horse-battery-staple", subject: "user-alice" },
	carol: { username: "carol", password: "carol-horse-battery-staple", subject: "user-carol" },
};
type User = (typeof users)[keyof typeof users];
const scene = faultScene({
	users: Object.values(users).map((u) => ({
		identifier: u.username,
		password: u.password,
		subject: u.subject,
	})),
	revocations: { credential, sources: ["198.51.100.0/24"] },
});

/** A session of the user's, so a revocation's followers have one to close. */
async function sessionOf(i: Instance, user: User) {
	const { username, password } = user;
	expect(said(await loginAt(i, nextSource(), { username, password }))).toEqual([
		200,
		undefined,
		true,
	]);
}

/** The ledger's revocation of a subject at the instance, from its block over https, as its proxy forwards it. */
async function revokeAt(i: Instance, subject: string) {
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
	return {
		status: res.status,
		error: body.error,
		state: body.state,
		complete: body.complete,
		at: performance.now(),
	};
}
type Revoked = Awaited<ReturnType<typeof revokeAt>>;
const said3 = (r: Revoked) => [r.status, r.error, r.state];
const complete = [200, undefined, undefined];
const uncounted = [503, "temporarily_unavailable", undefined];
const unknown = [503, "temporarily_unavailable", "unknown"];
const incomplete = [503, "temporarily_unavailable", "incomplete"];

/**
 * What a revocation answered, held to what the store took from `from` to its answer: done only where
 * the boundary, a follower's first write and its work (the subject's session closed) all succeeded;
 * incomplete only where the boundary did (a follower may have begun and not finished); unknown only
 * where no follower's write did.
 */
function heldToWrites(i: Instance, subject: string, from: number, r: Revoked) {
	const within = (m: Parameters<typeof successes>[1]) =>
		successes(i, m).filter((e) => e.at > from && e.at < r.at);
	const [boundary, followed] = [within(boundaryOf(subject)), within(closingAdded)];
	if (r.status === 200) {
		expect([...said3(r), r.complete]).toEqual([...complete, true]);
		expect(boundary.length).toBeGreaterThan(0);
		expect(followed.length).toBeGreaterThan(0);
		expect(within(sessionClosed).length).toBeGreaterThan(0);
		return "complete";
	}
	if (r.state === "incomplete") {
		expect(said3(r)).toEqual(incomplete);
		expect(boundary.length).toBeGreaterThan(0);
		return "incomplete";
	}
	expect(said3(r)).toEqual(unknown);
	expect(followed).toEqual([]);
	return "unknown";
}

/** The control: with no fault, the boundary is written, a follower runs, and done is answered. */
async function control(i: Instance) {
	await sessionOf(i, users.carol);
	const from = performance.now();
	const r = await revokeAt(i, users.carol.subject);
	expect(heldToWrites(i, users.carol.subject, from, r)).toBe("complete");
}

/** Healed: the topology has recovered and the instance is ready, and the revocation sent again, alice holding a new session for its followers, is done. */
async function healed(d: Deployed, i: Instance) {
	await recovered(d);
	await ready(i);
	// A revocation answered done during the fault closed her sessions; one with none to close writes no follower's.
	await sessionOf(i, users.alice);
	const from = performance.now();
	const r = await revokeAt(i, users.alice.subject);
	expect(heldToWrites(i, users.alice.subject, from, r)).toBe("complete");
}

/** A revocation of alice, who holds a session, held at the boundary's write: the fault comes after its window counted. */
async function heldAtBoundary(i: Instance) {
	await sessionOf(i, users.alice);
	const holding = i.relay.hold(boundaryOf(users.alice.subject));
	const asked = revokeAt(i, users.alice.subject);
	const held = await holding;
	return { held, asked };
}

describe("the ledger's revocation route answering done only once every step's dependency answered", () => {
	it("answers unavailable with no state while the network from the app to Redis is cut before its window counts [guarantee-3-l] {fault:Pu}", async () => {
		await on({ name: "ledger-unavailable-pu-window", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			await sessionOf(a, users.alice);
			const from = performance.now();
			a.relay.stall("up");
			const r = await revokeAt(a, users.alice.subject);
			a.relay.resume();
			// Stopped at the window: nothing past it was written, even once resumed.
			expect(said3(r)).toEqual(uncounted);
			await ready(a);
			expect(successes(a, boundaryOf(users.alice.subject)).filter((e) => e.at > from)).toEqual([]);
			await healed(d, a);
		});
	});

	it("answers unknown while the network from the app to Redis is cut at the boundary's write [guarantee-3-l] {fault:Pu}", async () => {
		await on({ name: "ledger-unavailable-pu-boundary", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const { held, asked } = await heldAtBoundary(a);
			const from = performance.now();
			a.relay.stall("up");
			held.release();
			const r = await asked;
			a.relay.resume();
			expect(said3(r)).toEqual(unknown);
			expect(heldToWrites(a, users.alice.subject, from, r)).toBe("unknown");
			// Nothing reached Redis while cut: no follower began, even once resumed.
			await ready(a);
			expect(successes(a, closingAdded).filter((e) => e.at > from)).toEqual([]);
			await healed(d, a);
		});
	});

	it("answers incomplete while the network from the app to Redis is cut at a follower's first write, the boundary written [guarantee-3-l] {fault:Pu}", async () => {
		await on({ name: "ledger-unavailable-pu-follower", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			await sessionOf(a, users.alice);
			const from = performance.now();
			const holding = a.relay.hold(closingAdded);
			const asked = revokeAt(a, users.alice.subject);
			// The followers begin only once the boundary's write is confirmed.
			const held = await holding;
			a.relay.stall("up");
			held.release();
			const r = await asked;
			a.relay.resume();
			expect(said3(r)).toEqual(incomplete);
			expect(heldToWrites(a, users.alice.subject, from, r)).toBe("incomplete");
			await healed(d, a);
		});
	});

	it("answers unknown while the network from Redis to the app is cut, the boundary written and never confirmed to it [guarantee-3-l] {fault:Pd}", async () => {
		await on({ name: "ledger-unavailable-pd", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const { held, asked } = await heldAtBoundary(a);
			const from = performance.now();
			a.relay.stall("down");
			held.release();
			const r = await asked;
			a.relay.resume();
			expect(said3(r)).toEqual(unknown);
			// Redis wrote the boundary before the route gave up; its answer was held.
			expect(
				a.relay.executions(boundaryOf(users.alice.subject)).some((e) => e.at > from && e.at < r.at),
			).toBe(true);
			await ready(a);
			expect(successes(a, closingAdded).filter((e) => e.at > from)).toEqual([]);
			await healed(d, a);
		});
	});

	it("answers done only where every step answered while every connection to Redis is cut as it opens [guarantee-3-l] {fault:R}", async ({
		annotate,
	}) => {
		await on({ name: "ledger-unavailable-r", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const { held, asked } = await heldAtBoundary(a);
			const cut = performance.now();
			// The held write goes with its connection.
			a.relay.reset("all");
			const cutting = setInterval(() => a.relay.reset("all"), 20);
			held.release();
			const r = await asked.finally(() => clearInterval(cutting));
			// Cuts 20 ms apart cannot stop a command, a resend of the boundary's write among them,
			// getting through on a connection just opened: the answer is held to the writes that
			// succeeded, done only where the boundary and a follower both did.
			await annotate(`answered ${heldToWrites(a, users.alice.subject, cut, r)}`);
			await healed(d, a);
		});
	});

	it("answers unknown while Redis answers later than the command timeout [guarantee-3-l] {fault:L}", async () => {
		await on({ name: "ledger-unavailable-l", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const { held, asked } = await heldAtBoundary(a);
			// Past the command timeout (1 s by default) each way.
			a.relay.delay(1_500, "both");
			const released = performance.now();
			held.release();
			const r = await asked;
			a.relay.delay(0, "both");
			expect(said3(r)).toEqual(unknown);
			expect(heldToWrites(a, users.alice.subject, released, r)).toBe("unknown");
			// The boundary's write reached Redis only past the command timeout, so no answer came in time.
			const first = a.relay
				.executions(boundaryOf(users.alice.subject))
				.find((e) => e.at > released);
			expect(first?.at).toBeGreaterThan(released + 1_000);
			await healed(d, a);
		});
	});

	it("answers unknown while Redis is too slow to run commands [guarantee-3-l] {fault:S}", async () => {
		await on({ name: "ledger-unavailable-s", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const { held, asked } = await heldAtBoundary(a);
			// The scene's value: the boundary's write is resent for about 25 s before the route gives up,
			// so Redis sleeps past the route's answer, and the answer is the slowness's.
			const { asleep, awake } = d.topology.sleep(d.topology.primary(), 40);
			const woke = awake.then(() => performance.now());
			await asleep;
			const released = performance.now();
			held.release();
			const r = await asked;
			expect(said3(r)).toEqual(unknown);
			expect(r.at).toBeLessThan(await woke);
			expect(
				a.relay
					.executions(boundaryOf(users.alice.subject))
					.filter((e) => e.at > released && e.at < r.at),
			).toEqual([]);
			await healed(d, a);
		});
	});

	it("answers unknown while the primary holds its writes for a promotion [guarantee-3-l] {fault:F}", async () => {
		await on({ name: "ledger-unavailable-f", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const { held, asked } = await heldAtBoundary(a);
			const [next, ...others] = d.topology.replicas();
			if (!next) throw new Error("a replica");
			const from = performance.now();
			let r: Revoked | undefined;
			await d.topology.promote({
				replica: next,
				reattach: others,
				// While the old primary holds its writes, before it goes.
				between: async () => {
					held.release();
					r = await asked;
				},
			});
			repointed(d);
			await replicasOnline(d);
			if (!r) throw new Error("the revocation was not answered during the promotion");
			expect(said3(r)).toEqual(unknown);
			expect(heldToWrites(a, users.alice.subject, from, r)).toBe("unknown");
			await healed(d, a);
		});
	});

	it("answers unknown for a boundary written on a server other than the one that confirmed it [guarantee-3-l] {fault:Fs}", async () => {
		await on({ name: "ledger-unavailable-fs", scene, replicas: 3 }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const old = d.topology.primary();
			const [, moved, follower] = d.topology.replicas();
			if (!moved || !follower) throw new Error("three replicas");
			// Two primaries first, the app still on the old one for both its connections.
			await d.topology.promote({ replica: moved, reattach: [follower], keepOld: true });
			const [oldId, newId] = [await old.runId(), await moved.runId()];
			expect(oldId).not.toBe(newId);
			const { asked } = await heldAtBoundary(a);
			// The held write goes with its connection; resent, it is written on the new primary.
			a.relay.switchUpstream(moved.upstream());
			const from = performance.now();
			a.relay.reset("operations");
			await reconnected(a, moved.upstream());
			const wait = await a.relay.observe(confirmation({ replicas: 1 }));
			const r = await asked;
			const upstreamOf = (id: number) => a.relay.connections().find((x) => x.id === id)?.upstream;
			// The boundary's write ran on the new primary, its confirmation passing on the old one.
			const written = a.relay
				.executions(boundaryOf(users.alice.subject))
				.filter((e) => e.at > from && e.at < wait.at)
				.at(-1);
			expect(written && runIdOf(written.reply)).toBe(newId);
			expect(written && upstreamOf(written.connection)).toEqual(moved.upstream());
			expect(upstreamOf(wait.connection)).toEqual(old.upstream());
			expect(said3(r)).toEqual(unknown);
			expect(heldToWrites(a, users.alice.subject, from, r)).toBe("unknown");
			a.relay.reset("confirming");
			await healed(d, a);
		});
	});

	it("answers done for a revocation made while Redis is killed at once and started again only where the server started again took every step [guarantee-3-l] {fault:C}", async ({
		annotate,
	}) => {
		await on({ name: "ledger-unavailable-c", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const { held, asked } = await heldAtBoundary(a);
			const from = performance.now();
			// Nothing reaches Redis until it is started again and the relay points at it, so every write
			// that lets the route answer done comes after.
			a.relay.stall("up");
			// The held write goes with its connection.
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			held.release();
			const runId = await d.topology.primary().runId();
			repointed(d);
			const restarted = performance.now();
			a.relay.resume();
			const r = await asked;
			const way = heldToWrites(a, users.alice.subject, from, r);
			if (way === "complete") {
				// Done only as the server started again answered the boundary and the follower.
				for (const m of [boundaryOf(users.alice.subject), closingAdded, sessionClosed]) {
					const kept = successes(a, m).filter((e) => e.at > from && e.at < r.at);
					expect(kept.every((e) => e.at > restarted && runIdOf(e.reply) === runId)).toBe(true);
				}
			}
			await annotate(`answered ${way}`);
			await replicasOnline(d);
			await healed(d, a);
		});
	});
});
