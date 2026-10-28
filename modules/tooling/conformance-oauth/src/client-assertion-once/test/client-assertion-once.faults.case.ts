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
	type Assertion,
	authenticatedAt,
	clientAssertion,
	clientSpendOf,
	keyedScene,
	on,
	said,
} from "../../faults/test/faults.ts";

const scene = keyedScene();
const refused = [401, "invalid_client"];
const issued = [200, "Bearer"];

/**
 * The control: with no fault, a client assertion's jti is spent by one write that succeeds, and the
 * assertion coming again is refused with no such write.
 */
async function control(i: Instance) {
	const a = clientAssertion();
	const seen = i.relay.observe(clientSpendOf(a));
	expect(said(await authenticatedAt(i, a))).toEqual(issued);
	await seen;
	expect(successes(i, clientSpendOf(a))).toHaveLength(1);
	expect(said(await authenticatedAt(i, a))).toEqual(refused);
	expect(successes(i, clientSpendOf(a))).toHaveLength(1);
}

/** After the fault: the assertion is refused as spent, and a new one authenticates. */
async function refusedAsSpent(i: Instance, a: Assertion) {
	expect(said(await authenticatedAt(i, a))).toEqual(refused);
	expect(said(await authenticatedAt(i, clientAssertion()))).toEqual(issued);
}

/** Every success of the assertion's spend is one send under one mark: it took effect once. */
const onceUnder = (
	i: Instance,
	a: Assertion,
	first: { command: Parameters<typeof sameMark>[0] },
) => {
	const effects = successes(i, clientSpendOf(a));
	expect(effects.length).toBeGreaterThan(0);
	expect(effects.every((e) => sameMark(first.command, e.command))).toBe(true);
};

describe("a client assertion's jti spent once under faults", () => {
	it("spends a client assertion's jti once whose spend's answer is lost once, the resend taking the first answer [guarantee-5-d] {fault:Lr}", async () => {
		await on({ name: "client-assertion-once-lr", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const a = clientAssertion();
			const drop = i.relay.dropReplyTo(clientSpendOf(a));
			const answer = await authenticatedAt(i, a);
			const dropped = await drop.first;
			expect(dropped.collateral.filter((x) => x.command.name === "EVAL")).toEqual([]);
			expect(said(answer)).toEqual(issued);
			expect(successes(i, clientSpendOf(a)).length).toBeGreaterThan(1);
			onceUnder(i, a, dropped);
			await refusedAsSpent(i, a);
		});
	});

	it("answers unavailable and gives no token when every answer to a spend is lost, the assertion then refused as spent [guarantee-5-d] {fault:Lx}", async () => {
		await on({ name: "client-assertion-once-lx", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const a = clientAssertion();
			const drop = i.relay.dropReplyTo(clientSpendOf(a), { resends: sameMark });
			const answer = await authenticatedAt(i, a);
			const dropped = await drop.first;
			drop.end();
			expect(drop.resends.length).toBeGreaterThan(0);
			expect(said(answer)).toEqual([503, "temporarily_unavailable"]);
			expect(answer.body.access_token).toBeUndefined();
			onceUnder(i, a, dropped);
			await ready(i);
			await refusedAsSpent(i, a);
		});
	});

	it("refuses a client assertion spent before a caught-up replica is promoted [guarantee-5-d] {fault:F}", async () => {
		await on({ name: "client-assertion-once-f", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const a = clientAssertion();
			expect(said(await authenticatedAt(i, a))).toEqual(issued);
			await failover(d);
			await ready(i);
			await refusedAsSpent(i, a);
		});
	});

	it("refuses a client assertion spent before Redis is killed at once and started again [guarantee-5-d] {fault:C}", async () => {
		await on({ name: "client-assertion-once-c", scene }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const a = clientAssertion();
			expect(said(await authenticatedAt(i, a))).toEqual(issued);
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			repointed(d);
			await replicasOnline(d);
			await ready(i);
			await refusedAsSpent(i, a);
		});
	});

	it("refuses, at another instance, a client assertion whose instance was killed after spending it and before answering [guarantee-5-d] {fault:K}", async () => {
		await on({ name: "client-assertion-once-k", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const sent = clientAssertion();
			// The spend's confirmation held once the spend has run, before the instance can answer.
			let held: Promise<unknown> | undefined;
			const spent = a.relay.observe(clientSpendOf(sent)).then((e) => {
				held = a.relay.hold(confirmation({ replicas: 1 }));
				return e;
			});
			const answer = authenticatedAt(a, sent).catch(() => undefined);
			await spent;
			await held;
			const ended = await a.kill();
			expect(ended.signal).toBe("SIGKILL");
			expect((await answer)?.body.access_token).toBeUndefined();
			expect(successes(a, clientSpendOf(sent))).toHaveLength(1);
			await ready(b);
			await refusedAsSpent(b, sent);
		});
	});

	it("spends once for one client assertion sent to two instances at once, the later spend finding it spent [guarantee-5-d] {fault:H2}", async () => {
		await on({ name: "client-assertion-once-h2", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const sent = clientAssertion();
			// Both have checked the assertion and are about to spend it.
			const [heldA, heldB] = [a.relay.hold(clientSpendOf(sent)), b.relay.hold(clientSpendOf(sent))];
			const [atA, atB] = [authenticatedAt(a, sent), authenticatedAt(b, sent)];
			const [first, second] = await Promise.all([heldA, heldB]);
			first.release();
			expect(said(await atA)).toEqual(issued);
			second.release();
			expect(said(await atB)).toEqual(refused);
			expect(
				successes(a, clientSpendOf(sent)).length + successes(b, clientSpendOf(sent)).length,
			).toBe(1);
			await refusedAsSpent(b, sent);
		});
	});

	it("authenticates at most once by one client assertion whose two spends at two instances are let go together [guarantee-5-d] {fault:H2}", async () => {
		await on({ name: "client-assertion-once-h2-together", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const sent = clientAssertion();
			const holds = [a.relay.hold(clientSpendOf(sent)), b.relay.hold(clientSpendOf(sent))];
			const answers = Promise.all([authenticatedAt(a, sent), authenticatedAt(b, sent)]);
			for (const held of await Promise.all(holds)) held.release();
			const both = (await answers).map(said);
			expect(both.filter((s) => s[0] === 200).length).toBeLessThanOrEqual(1);
			// One spend takes effect; the other finds it spent and is refused as a replay.
			expect(
				successes(a, clientSpendOf(sent)).length + successes(b, clientSpendOf(sent)).length,
			).toBe(1);
			expect(both.filter((s) => s[0] !== 200).every((s) => s[1] === "invalid_client")).toBe(true);
			await refusedAsSpent(b, sent);
		});
	});
});
