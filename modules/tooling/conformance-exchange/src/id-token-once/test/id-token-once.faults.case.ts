import {
	confirmation,
	type Deployed,
	failover,
	type Instance,
	instanceOf,
	ready,
	replicasOnline,
	repointed,
	sameMark,
	successes,
} from "@mod/conformance/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	type Apple,
	appleScene,
	assertedAt,
	exchangedAt,
	idToken,
	startApple,
} from "../../faults/test/apple.ts";
import { type Answer, on, said } from "../../faults/test/faults.ts";
import { takenOf } from "../../faults/test/wire.ts";

// One id_token, one record of those taken, for both grants: the token exchange issues and then takes
// it, giving back what it issued where the record finds it taken; the JWT bearer grant takes it before
// it issues. The faults are on the exchange's take, and two instances cross the two grants.

const issued = [200, "Bearer"];

/** Refused by the token exchange as taken, by its own description. */
const usedAtExchange = (answer: Answer) =>
	expect([answer.status, answer.body.error, answer.body.error_description]).toEqual([
		400,
		"invalid_request",
		"subject_token has been used",
	]);

/** Refused by the JWT bearer grant as taken: an expired one is `invalid_grant` too, told by its description. */
const replayed = (answer: Answer) =>
	expect([answer.status, answer.body.error, answer.body.error_description]).toEqual([
		400,
		"invalid_grant",
		"assertion replayed",
	]);

let apple: Apple | undefined;
beforeAll(async () => {
	apple = await startApple();
});
afterAll(async () => {
	await apple?.stop();
});

/** A scene on a deployment of its own, its instances reaching Apple's host and trusting it. */
const onApple = (
	o: { readonly name: string; readonly instances?: number },
	scene: (d: Deployed) => Promise<void>,
) => {
	if (!apple) throw new Error("Apple's host is not up");
	return on({ ...o, scene: appleScene(apple), trustedCertificates: [apple.trusted] }, scene);
};

/**
 * The control: with no fault, an id_token is taken by one write that succeeds, by either grant, and
 * then refused by both with no such write.
 */
async function control(i: Instance) {
	for (const take of [exchangedAt, assertedAt]) {
		const token = await idToken();
		const seen = i.relay.observe(takenOf(token));
		expect(said(await take(i, token))).toEqual(issued);
		await seen;
		expect(successes(i, takenOf(token))).toHaveLength(1);
		usedAtExchange(await exchangedAt(i, token));
		replayed(await assertedAt(i, token));
		expect(successes(i, takenOf(token))).toHaveLength(1);
	}
}

/**
 * After the fault: the id_token is refused by both grants, each by its take, sent and finding it
 * taken, and a new one is exchanged.
 */
async function refusedAsTaken(i: Instance, token: string) {
	const [sent, took] = [i.relay.executions(takenOf(token)).length, successes(i, takenOf(token))];
	const answers = [await exchangedAt(i, token), await assertedAt(i, token)];
	usedAtExchange(answers[0] as Answer);
	replayed(answers[1] as Answer);
	expect(answers.map((a) => a.body.access_token)).toEqual([undefined, undefined]);
	expect(i.relay.executions(takenOf(token)).length).toBeGreaterThanOrEqual(sent + 2);
	expect(successes(i, takenOf(token))).toEqual(took);
	expect(said(await exchangedAt(i, await idToken()))).toEqual(issued);
}

/** Every success of the id_token's take is one send under one mark: it took effect once. */
const onceUnder = (
	i: Instance,
	token: string,
	first: { command: Parameters<typeof sameMark>[0] },
) => {
	const effects = successes(i, takenOf(token));
	expect(effects.length).toBeGreaterThan(0);
	expect(effects.every((e) => sameMark(first.command, e.command))).toBe(true);
};

describe("an id_token exchanged once, by the token exchange or as a JWT bearer assertion, under faults", () => {
	it("takes an id_token once whose exchange's take loses its answer once, the resend taking the first answer [guarantee-5-j] {fault:Lr}", async () => {
		await onApple({ name: "id-token-once-lr" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await idToken();
			const drop = i.relay.dropReplyTo(takenOf(token));
			const answer = await exchangedAt(i, token);
			const dropped = await drop.first;
			expect(dropped.collateral.filter((x) => x.command.name === "EVAL")).toEqual([]);
			expect(said(answer)).toEqual(issued);
			expect(successes(i, takenOf(token)).length).toBeGreaterThan(1);
			onceUnder(i, token, dropped);
			await refusedAsTaken(i, token);
		});
	});

	it("answers unavailable and gives no token when every answer to the exchange's take is lost, the id_token then refused by both grants [guarantee-5-j] {fault:Lx}", async () => {
		await onApple({ name: "id-token-once-lx" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await idToken();
			const drop = i.relay.dropReplyTo(takenOf(token), { resends: sameMark });
			const answer = await exchangedAt(i, token);
			const dropped = await drop.first;
			drop.end();
			expect(drop.resends.length).toBeGreaterThan(0);
			expect(said(answer)).toEqual([503, "temporarily_unavailable"]);
			expect(answer.body.access_token).toBeUndefined();
			onceUnder(i, token, dropped);
			await ready(i);
			await refusedAsTaken(i, token);
		});
	});

	it("refuses an id_token exchanged before a caught-up replica is promoted [guarantee-5-j] {fault:F}", async () => {
		await onApple({ name: "id-token-once-f" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await idToken();
			expect(said(await exchangedAt(i, token))).toEqual(issued);
			await failover(d);
			await ready(i);
			await refusedAsTaken(i, token);
		});
	});

	it("refuses an id_token exchanged before Redis is killed at once and started again [guarantee-5-j] {fault:C}", async () => {
		await onApple({ name: "id-token-once-c" }, async (d) => {
			const i = instanceOf(d);
			await control(i);
			const token = await idToken();
			expect(said(await exchangedAt(i, token))).toEqual(issued);
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			repointed(d);
			await replicasOnline(d);
			await ready(i);
			await refusedAsTaken(i, token);
		});
	});

	it("refuses, at another instance, an id_token whose instance was killed after the exchange took it and before answering [guarantee-5-j] {fault:K}", async () => {
		await onApple({ name: "id-token-once-k", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const token = await idToken();
			// The take's confirmation held once the take has run, before the instance can answer.
			let held: Promise<unknown> | undefined;
			const taken = a.relay.observe(takenOf(token)).then((e) => {
				held = a.relay.hold(confirmation({ replicas: 1 }));
				return e;
			});
			const answer = exchangedAt(a, token).catch(() => undefined);
			await taken;
			await held;
			const ended = await a.kill();
			expect(ended.signal).toBe("SIGKILL");
			expect((await answer)?.body.access_token).toBeUndefined();
			expect(successes(a, takenOf(token))).toHaveLength(1);
			await ready(b);
			await refusedAsTaken(b, token);
		});
	});

	it("takes once one id_token exchanged at one instance and asserted at another at once, the exchange finding it taken giving back what it issued [guarantee-5-j] {fault:H2}", async () => {
		await onApple({ name: "id-token-once-h2", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const token = await idToken();
			// Both have checked the id_token and are about to take it; the exchange has issued.
			const [heldA, heldB] = [a.relay.hold(takenOf(token)), b.relay.hold(takenOf(token))];
			const [atA, atB] = [exchangedAt(a, token), assertedAt(b, token)];
			const [exchanging, asserting] = await Promise.all([heldA, heldB]);
			asserting.release();
			expect(said(await atB)).toEqual(issued);
			exchanging.release();
			const late = await atA;
			usedAtExchange(late);
			expect(late.body.access_token).toBeUndefined();
			expect(successes(a, takenOf(token)).length + successes(b, takenOf(token)).length).toBe(1);
			await refusedAsTaken(a, token);
		});
	});

	it("issues at most once for one id_token whose takes by the two grants at two instances are let go together [guarantee-5-j] {fault:H2}", async () => {
		await onApple({ name: "id-token-once-h2-together", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const token = await idToken();
			const holds = [a.relay.hold(takenOf(token)), b.relay.hold(takenOf(token))];
			const answers = Promise.all([exchangedAt(a, token), assertedAt(b, token)]);
			for (const held of await Promise.all(holds)) held.release();
			const [exchanged, asserted] = await answers;
			expect([exchanged, asserted].filter((x) => x.status === 200).length).toBeLessThanOrEqual(1);
			// One take takes effect; the other finds it taken and is refused by its own grant.
			expect(successes(a, takenOf(token)).length + successes(b, takenOf(token)).length).toBe(1);
			if (exchanged.status !== 200) usedAtExchange(exchanged);
			if (asserted.status !== 200) replayed(asserted);
			await refusedAsTaken(b, token);
		});
	});
});
