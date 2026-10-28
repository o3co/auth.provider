import {
	confirmation,
	failover,
	type Instance,
	instanceOf,
	ready,
	replicasOnline,
	repointed,
	sameMark,
	successes,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import {
	dpopScene,
	on,
	type Proof,
	proof,
	proofSpendOf,
	provenAt,
	said,
} from "../../faults/test/faults.ts";

const scene = dpopScene();
const refused = [400, "invalid_dpop_proof"];
const issued = [200, "DPoP"];

/**
 * The control: with no fault, a DPoP proof's jti is spent by one write that succeeds, and the
 * proof coming again is refused with no such write.
 */
async function control(i: Instance) {
	const p = await proof();
	const seen = i.relay.observe(proofSpendOf(p));
	expect(said(await provenAt(i, p))).toEqual(issued);
	await seen;
	expect(successes(i, proofSpendOf(p))).toHaveLength(1);
	expect(said(await provenAt(i, p))).toEqual(refused);
	expect(successes(i, proofSpendOf(p))).toHaveLength(1);
}

/**
 * After the fault: the proof is refused as used before, and a new one is taken. Each scene ends well
 * within the proof's window (`dpop.proof-window`, a minute unless set), so the refusal is the spend's.
 */
async function refusedAsSpent(i: Instance, p: Proof) {
	expect(said(await provenAt(i, p))).toEqual(refused);
	expect(said(await provenAt(i, await proof()))).toEqual(issued);
}

/** Every success of the proof's spend is one send under one mark: it took effect once. */
const onceUnder = (i: Instance, p: Proof, first: { command: Parameters<typeof sameMark>[0] }) => {
	const effects = successes(i, proofSpendOf(p));
	expect(effects.length).toBeGreaterThan(0);
	expect(effects.every((e) => sameMark(first.command, e.command))).toBe(true);
};

describe("a DPoP proof's jti spent once under faults", () => {
	it("spends a DPoP proof's jti once whose spend's answer is lost once, the resend taking the first answer [guarantee-5-e] {fault:Lr}", async () => {
		await on({ name: "dpop-once-lr", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const p = await proof();
			const drop = i.relay.dropReplyTo(proofSpendOf(p));
			const answer = await provenAt(i, p);
			const dropped = await drop.first;
			expect(dropped.collateral.filter((x) => x.command.name === "EVAL")).toEqual([]);
			expect(said(answer)).toEqual(issued);
			expect(successes(i, proofSpendOf(p)).length).toBeGreaterThan(1);
			onceUnder(i, p, dropped);
			await refusedAsSpent(i, p);
		});
	});

	it("answers unavailable and gives no token when every answer to a spend is lost, the proof then refused as used before [guarantee-5-e] {fault:Lx}", async () => {
		await on({ name: "dpop-once-lx", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const p = await proof();
			const drop = i.relay.dropReplyTo(proofSpendOf(p), { resends: sameMark });
			const answer = await provenAt(i, p);
			const dropped = await drop.first;
			drop.end();
			expect(drop.resends.length).toBeGreaterThan(0);
			expect(said(answer)).toEqual([503, "temporarily_unavailable"]);
			expect(answer.body.access_token).toBeUndefined();
			onceUnder(i, p, dropped);
			await ready(i);
			await refusedAsSpent(i, p);
		});
	});

	it("refuses a DPoP proof spent before a caught-up replica is promoted [guarantee-5-e] {fault:F}", async () => {
		await on({ name: "dpop-once-f", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const p = await proof();
			expect(said(await provenAt(i, p))).toEqual(issued);
			await failover(d);
			await ready(i);
			await refusedAsSpent(i, p);
		});
	});

	it("refuses a DPoP proof spent before Redis is killed at once and started again [guarantee-5-e] {fault:C}", async () => {
		await on({ name: "dpop-once-c", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const p = await proof();
			expect(said(await provenAt(i, p))).toEqual(issued);
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			repointed(d);
			await replicasOnline(d);
			await ready(i);
			await refusedAsSpent(i, p);
		});
	});

	it("refuses, at another instance, a DPoP proof whose instance was killed after spending it and before answering [guarantee-5-e] {fault:K}", async () => {
		await on({ name: "dpop-once-k", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const sent = await proof();
			// The spend's confirmation held once the spend has run, before the instance can answer.
			let held: Promise<unknown> | undefined;
			const spent = a.relay.observe(proofSpendOf(sent)).then((e) => {
				held = a.relay.hold(confirmation({ replicas: 1 }));
				return e;
			});
			const answer = provenAt(a, sent).catch(() => undefined);
			await spent;
			await held;
			const ended = await a.kill();
			expect(ended.signal).toBe("SIGKILL");
			expect((await answer)?.body.access_token).toBeUndefined();
			expect(successes(a, proofSpendOf(sent))).toHaveLength(1);
			await ready(b);
			await refusedAsSpent(b, sent);
		});
	});

	it("spends once for one DPoP proof sent to two instances at once, the later spend finding it spent [guarantee-5-e] {fault:H2}", async () => {
		await on({ name: "dpop-once-h2", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const sent = await proof();
			// Both have checked the proof and are about to spend it.
			const [heldA, heldB] = [a.relay.hold(proofSpendOf(sent)), b.relay.hold(proofSpendOf(sent))];
			const [atA, atB] = [provenAt(a, sent), provenAt(b, sent)];
			const [first, second] = await Promise.all([heldA, heldB]);
			first.release();
			expect(said(await atA)).toEqual(issued);
			second.release();
			expect(said(await atB)).toEqual(refused);
			expect(
				successes(a, proofSpendOf(sent)).length + successes(b, proofSpendOf(sent)).length,
			).toBe(1);
			await refusedAsSpent(b, sent);
		});
	});

	it("issues at most once for one DPoP proof whose two spends at two instances are let go together [guarantee-5-e] {fault:H2}", async () => {
		await on({ name: "dpop-once-h2-together", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const sent = await proof();
			const holds = [a.relay.hold(proofSpendOf(sent)), b.relay.hold(proofSpendOf(sent))];
			const answers = Promise.all([provenAt(a, sent), provenAt(b, sent)]);
			for (const held of await Promise.all(holds)) held.release();
			const both = (await answers).map(said);
			expect(both.filter((s) => s[0] === 200).length).toBeLessThanOrEqual(1);
			// One spend takes effect; the other finds it spent and is refused as a replay.
			expect(
				successes(a, proofSpendOf(sent)).length + successes(b, proofSpendOf(sent)).length,
			).toBe(1);
			expect(both.filter((s) => s[0] !== 200).every((s) => s[1] === "invalid_dpop_proof")).toBe(
				true,
			);
			await refusedAsSpent(b, sent);
		});
	});
});
