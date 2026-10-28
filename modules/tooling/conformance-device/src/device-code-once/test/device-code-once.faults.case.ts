import {
	confirmation,
	failover,
	type Instance,
	instanceOf,
	type Match,
	ready,
	replicasOnline,
	repointed,
	sameMark,
	successes,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import {
	approvedAt,
	type Device,
	decideAt,
	deviceAt,
	loginAt,
	on,
	pollAt,
	said,
} from "../../faults/test/faults.ts";
import { confirmedOf, decisionOf, isStoreCall, takeOf } from "../../faults/test/wire.ts";

const issued = [200, "Bearer"];
// A taken code answers no description, as an unknown one does; an expired one answers `expired_token`.
const refused = [400, "invalid_grant"];

/**
 * The control: with no fault, a poll takes a device's approval by one write that succeeds, and a
 * poll coming again is refused with no such write.
 */
async function control(i: Instance) {
	const d = await approvedAt(i);
	const seen = i.relay.observe(takeOf(d));
	expect(said(await pollAt(i, d))).toEqual(issued);
	await seen;
	expect(successes(i, takeOf(d))).toHaveLength(1);
	expect(said(await pollAt(i, d))).toEqual(refused);
	expect(successes(i, takeOf(d))).toHaveLength(1);
}

/**
 * After the fault: the device is refused as taken, with no take of its own, while its record is still
 * kept: polled by its own client, a kept device answers `invalid_grant` only once taken (a pending one
 * answers `authorization_pending`, an approved one issues), and a lost one is looked up as unknown.
 * Then a new device is issued.
 */
async function refusedAsTaken(i: Instance, d: Device) {
	const took = successes(i, takeOf(d));
	expect(said(await pollAt(i, d))).toEqual(refused);
	expect(successes(i, takeOf(d))).toEqual(took);
	const kept = await decideAt(i, await loginAt(i), "lookup", d);
	expect([kept.status, kept.body.client_id]).toEqual([200, "tv"]);
	expect(said(await pollAt(i, await approvedAt(i)))).toEqual(issued);
}

/** Every success of the device's take is one send under one mark: it took effect once. */
const onceUnder = (i: Instance, d: Device, first: { command: Parameters<typeof sameMark>[0] }) => {
	const effects = successes(i, takeOf(d));
	expect(effects.length).toBeGreaterThan(0);
	expect(effects.every((e) => sameMark(first.command, e.command))).toBe(true);
};

/**
 * A write that lost its race at the instance: sent on what it read, sent again only under its own mark
 * (a resend, never a second decision), and never taking effect.
 */
const lostOnly = (i: Instance, match: Match) => {
	const sent = i.relay.executions(match);
	expect(sent.length).toBeGreaterThan(0);
	expect(
		sent.every((e) => !e.succeeded && sameMark(sent[0]?.command ?? e.command, e.command)),
	).toBe(true);
};

describe("a device code decided and redeemed once under faults", () => {
	it("issues once for a device whose take's answer is lost once, the resend taking the first answer [guarantee-5-f] {fault:Lr}", async () => {
		await on({ name: "device-code-once-lr" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const dv = await approvedAt(i);
			const drop = i.relay.dropReplyTo(takeOf(dv));
			const answer = await pollAt(i, dv);
			const dropped = await drop.first;
			// Nothing but the take was cut with its answer.
			expect(dropped.collateral.filter((x) => isStoreCall(x.command))).toEqual([]);
			expect(said(answer)).toEqual(issued);
			expect(successes(i, takeOf(dv)).length).toBeGreaterThan(1);
			onceUnder(i, dv, dropped);
			await refusedAsTaken(i, dv);
		});
	});

	it("answers unavailable and issues nothing when every answer to a take is lost, the device then refused as taken [guarantee-5-f] {fault:Lx}", async () => {
		await on({ name: "device-code-once-lx" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const dv = await approvedAt(i);
			const drop = i.relay.dropReplyTo(takeOf(dv), { resends: sameMark });
			const answer = await pollAt(i, dv);
			const dropped = await drop.first;
			drop.end();
			expect(drop.resends.length).toBeGreaterThan(0);
			expect(said(answer)).toEqual([503, "temporarily_unavailable"]);
			expect(answer.body.access_token).toBeUndefined();
			onceUnder(i, dv, dropped);
			await ready(i);
			await refusedAsTaken(i, dv);
		});
	});

	it("refuses a device redeemed before a caught-up replica is promoted [guarantee-5-f] {fault:F}", async () => {
		await on({ name: "device-code-once-f" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const dv = await approvedAt(i);
			expect(said(await pollAt(i, dv))).toEqual(issued);
			const before = await d.topology.primary().runId();
			await failover(d);
			expect(await d.topology.primary().runId()).not.toBe(before);
			await ready(i);
			await refusedAsTaken(i, dv);
		});
	});

	it("refuses a device redeemed before Redis is killed at once and started again [guarantee-5-f] {fault:C}", async () => {
		await on({ name: "device-code-once-c" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const dv = await approvedAt(i);
			expect(said(await pollAt(i, dv))).toEqual(issued);
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			repointed(d);
			await replicasOnline(d);
			await ready(i);
			await refusedAsTaken(i, dv);
		});
	});

	it("refuses, at another instance, a device whose instance was killed after taking its approval and before answering [guarantee-5-f] {fault:K}", async () => {
		await on({ name: "device-code-once-k", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const dv = await approvedAt(a);
			// The take's confirmation held once the take has run, before the instance can answer.
			let held: Promise<unknown> | undefined;
			const taken = a.relay.observe(takeOf(dv)).then((e) => {
				held = a.relay.hold(confirmation({ replicas: 1 }));
				return e;
			});
			const answer = pollAt(a, dv).catch(() => undefined);
			await taken;
			await held;
			const ended = await a.kill();
			expect(ended.signal).toBe("SIGKILL");
			expect((await answer)?.body.access_token).toBeUndefined();
			expect(successes(a, takeOf(dv))).toHaveLength(1);
			await ready(b);
			await refusedAsTaken(b, dv);
		});
	});

	it("issues once for one device polled at two instances at once, the later take finding it taken [guarantee-5-f] {fault:H2}", async () => {
		await on({ name: "device-code-once-h2", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const dv = await approvedAt(a);
			// Both have read the approval and are about to take it.
			const [heldA, heldB] = [a.relay.hold(takeOf(dv)), b.relay.hold(takeOf(dv))];
			const [atA, atB] = [pollAt(a, dv), pollAt(b, dv)];
			const [first, second] = await Promise.all([heldA, heldB]);
			first.release();
			expect(said(await atA)).toEqual(issued);
			second.release();
			expect(said(await atB)).toEqual(refused);
			// The later take lost on the version it read, read the record taken, and confirmed it.
			lostOnly(b, takeOf(dv));
			expect(b.relay.executions(confirmedOf(dv)).length).toBeGreaterThan(0);
			expect(successes(a, takeOf(dv)).length + successes(b, takeOf(dv)).length).toBe(1);
			await refusedAsTaken(b, dv);
		});
	});

	it("issues at most once for one device whose two takes at two instances are let go together [guarantee-5-f] {fault:H2}", async () => {
		await on({ name: "device-code-once-h2-together", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const dv = await approvedAt(a);
			const holds = [a.relay.hold(takeOf(dv)), b.relay.hold(takeOf(dv))];
			const answers = Promise.all([pollAt(a, dv), pollAt(b, dv)]);
			for (const held of await Promise.all(holds)) held.release();
			const both = (await answers).map(said);
			expect(both.filter((s) => s[0] === 200).length).toBeLessThanOrEqual(1);
			// One take takes effect; the other finds the record taken and is refused.
			expect(successes(a, takeOf(dv)).length + successes(b, takeOf(dv)).length).toBe(1);
			for (const s of both.filter((s) => s[0] !== 200)) expect(s).toEqual(refused);
			await refusedAsTaken(b, dv);
		});
	});

	it("decides a device once that is approved at one instance and denied at another at once, its poll following the decision that stood [guarantee-5-f] {fault:H2}", async () => {
		await on({ name: "device-code-once-h2-decided", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const dv = await deviceAt(a);
			const [atA, atB] = [await loginAt(a), await loginAt(b)];
			// Both have read the device pending and are about to decide it.
			const approval = decisionOf(dv, "approved");
			const denial = decisionOf(dv, "denied");
			const [heldA, heldB] = [a.relay.hold(approval), b.relay.hold(denial)];
			const [approving, denying] = [decideAt(a, atA, "approve", dv), decideAt(b, atB, "deny", dv)];
			const [first, second] = await Promise.all([heldA, heldB]);
			first.release();
			expect((await approving).body).toEqual({ status: "approved", client_id: "tv" });
			second.release();
			const later = await denying;
			expect([later.status, later.body.error]).toEqual([409, "already_decided"]);
			// The denial lost on the version it read, read the device approved, and confirmed it.
			lostOnly(b, denial);
			expect(b.relay.executions(confirmedOf(dv)).length).toBeGreaterThan(0);
			expect(successes(a, approval)).toHaveLength(1);
			expect(said(await pollAt(b, dv))).toEqual(issued);
			await refusedAsTaken(b, dv);
		});
	});
});
