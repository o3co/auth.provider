import type { SentEvent } from "@mod/conformance";
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
	type Answer,
	type Assertion,
	type Authenticator,
	assertionAt,
	challengeLifetimeMs,
	loginAt,
	on,
	registeredAt,
	said,
} from "../../faults/test/faults.ts";
import { isStoreCall, takeOf } from "../../faults/test/wire.ts";

// A challenge's take writes its record taken on every assertion of a challenge still kept, the first
// and every one after it alike, each a write that succeeds; and a take that loses a race reads again
// and writes again. So the successes of the take do not count the challenge's uses, as the spends of
// other artifacts do. The scenes tell a challenge used once by what they can count, on every instance
// together: the tokens issued for the assertion, at most one; every other use of it refused with the
// reason the instance records, `challenge_invalid`; and every use's take reaching the store, so a
// refusal was the store's, not one before it. A challenge never asked for is not the case, as the
// first use found it; nor one ended by its age, as each use comes well within its life.

const issued = [200, "Bearer"];
// Every refusal of a passkey assertion answers alike, so it never tells whether a passkey is held.
const refused = [400, "invalid_grant"];

/** One use of an assertion at an instance: its answer (none where the instance ended), what the instance recorded, and whether its take reached the store. */
interface Use {
	readonly answer: Answer | undefined;
	readonly events: readonly SentEvent[];
	readonly reached: boolean;
}

/** Uses the assertion at the instance, well within its challenge's life. */
async function useAt(i: Instance, a: Assertion): Promise<Use> {
	expect(Date.now() - a.askedAt).toBeLessThan(challengeLifetimeMs / 2);
	const sent = i.relay.executions(takeOf(a.challenge)).length;
	const { result, events } = await i.audit.during(() => loginAt(i, a).catch(() => undefined));
	return { answer: result, events, reached: i.relay.executions(takeOf(a.challenge)).length > sent };
}

/** The tokens the instances issued over the uses, as they recorded them. */
const issuedOver = (uses: readonly Use[]) =>
	uses.flatMap((u) => u.events).filter((e) => e.kind === "token.issued").length;

/** A use refused as its challenge not open, the store having been asked. */
function refusedAsUsed(u: Use) {
	expect(u.answer && said(u.answer)).toEqual(refused);
	expect(
		u.events.filter((e) => e.kind === "passkey.login.refused").map((e) => e.attributes?.reason),
	).toEqual(["challenge_invalid"]);
}

/**
 * The challenge used once over the uses of its assertion: `tokens` issued on every instance together,
 * every use's take reaching the store, and every use but the one issued refused as its challenge not
 * open. Then a new assertion is issued a token at the instance.
 */
async function usedOnce(
	uses: readonly Use[],
	tokens: number,
	i: Instance,
	authenticator: Authenticator,
) {
	expect(issuedOver(uses)).toBe(tokens);
	expect(uses.filter((u) => u.answer?.status === 200)).toHaveLength(Math.min(tokens, 1));
	expect(uses.every((u) => u.reached)).toBe(true);
	for (const u of uses.slice(1).filter((u) => u.answer?.status !== 200)) refusedAsUsed(u);
	expect(said(await loginAt(i, await assertionAt(i, authenticator)))).toEqual(issued);
}

/**
 * The control: with no fault, an assertion's challenge is taken and a token issued, and the assertion
 * coming again is refused as its challenge not open.
 */
async function control(i: Instance, authenticator: Authenticator) {
	const a = await assertionAt(i, authenticator);
	const first = await useAt(i, a);
	expect(first.answer && said(first.answer)).toEqual(issued);
	await usedOnce([first, await useAt(i, a)], 1, i, authenticator);
}

/** Every success of the challenge's take so far is one send under one mark: it was sent once, and resent. */
const onceUnder = (
	i: Instance,
	a: Assertion,
	first: { command: Parameters<typeof sameMark>[0] },
) => {
	const effects = successes(i, takeOf(a.challenge));
	expect(effects.length).toBeGreaterThan(0);
	expect(effects.every((e) => sameMark(first.command, e.command))).toBe(true);
};

describe("a passkey challenge used once under faults", () => {
	it("issues once for an assertion whose challenge's take loses its answer once, the resend taking the first answer [guarantee-5-h] {fault:Lr}", async () => {
		await on({ name: "passkey-challenge-once-lr" }, async (d) => {
			const i = instanceOf(d);
			const authenticator = await registeredAt(i);
			await control(i, authenticator);
			const a = await assertionAt(i, authenticator);
			const drop = i.relay.dropReplyTo(takeOf(a.challenge));
			const first = await useAt(i, a);
			const dropped = await drop.first;
			// Nothing but the take was cut with its answer.
			expect(dropped.collateral.filter((x) => isStoreCall(x.command))).toEqual([]);
			expect(first.answer && said(first.answer)).toEqual(issued);
			// The dropped send and its resend, before the assertion comes again.
			expect(successes(i, takeOf(a.challenge)).length).toBeGreaterThan(1);
			onceUnder(i, a, dropped);
			await usedOnce([first, await useAt(i, a)], 1, i, authenticator);
		});
	});

	it("answers unavailable and issues nothing when every answer to a challenge's take is lost, the assertion then refused [guarantee-5-h] {fault:Lx}", async () => {
		await on({ name: "passkey-challenge-once-lx" }, async (d) => {
			const i = instanceOf(d);
			const authenticator = await registeredAt(i);
			await control(i, authenticator);
			const a = await assertionAt(i, authenticator);
			const drop = i.relay.dropReplyTo(takeOf(a.challenge), { resends: sameMark });
			const first = await useAt(i, a);
			const dropped = await drop.first;
			drop.end();
			expect(drop.resends.length).toBeGreaterThan(0);
			expect(first.answer && said(first.answer)).toEqual([503, "temporarily_unavailable"]);
			onceUnder(i, a, dropped);
			await ready(i);
			// The take went through, though its answer never came back: none is issued.
			await usedOnce([first, await useAt(i, a)], 0, i, authenticator);
		});
	});

	it("refuses an assertion whose challenge was used before a caught-up replica is promoted [guarantee-5-h] {fault:F}", async () => {
		await on({ name: "passkey-challenge-once-f" }, async (d) => {
			const i = instanceOf(d);
			const authenticator = await registeredAt(i);
			await control(i, authenticator);
			const a = await assertionAt(i, authenticator);
			const first = await useAt(i, a);
			expect(first.answer && said(first.answer)).toEqual(issued);
			const before = await d.topology.primary().runId();
			await failover(d);
			expect(await d.topology.primary().runId()).not.toBe(before);
			await ready(i);
			await usedOnce([first, await useAt(i, a)], 1, i, authenticator);
		});
	});

	it("refuses an assertion whose challenge was used before Redis is killed at once and started again [guarantee-5-h] {fault:C}", async () => {
		await on({ name: "passkey-challenge-once-c" }, async (d) => {
			const i = instanceOf(d);
			const authenticator = await registeredAt(i);
			await control(i, authenticator);
			const a = await assertionAt(i, authenticator);
			const first = await useAt(i, a);
			expect(first.answer && said(first.answer)).toEqual(issued);
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			repointed(d);
			await replicasOnline(d);
			await ready(i);
			await usedOnce([first, await useAt(i, a)], 1, i, authenticator);
		});
	});

	it("refuses, at another instance, an assertion whose instance was killed after taking its challenge and before answering [guarantee-5-h] {fault:K}", async () => {
		await on({ name: "passkey-challenge-once-k", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			const authenticator = await registeredAt(a);
			await control(a, authenticator);
			const sent = await assertionAt(a, authenticator);
			// The take's confirmation held once the take has run, before the instance can issue.
			let held: Promise<unknown> | undefined;
			const taken = a.relay.observe(takeOf(sent.challenge)).then((e) => {
				held = a.relay.hold(confirmation({ replicas: 1 }));
				return e;
			});
			const using = useAt(a, sent);
			await taken;
			await held;
			const ended = await a.kill();
			expect(ended.signal).toBe("SIGKILL");
			const first = await using;
			// Cut short, or answered 502 by the trace in front of the ended instance: no token either way.
			expect(first.answer?.body.access_token).toBeUndefined();
			await ready(b);
			// The take went through, and the instance ended before it issued: none is issued.
			await usedOnce([first, await useAt(b, sent)], 0, b, authenticator);
		});
	});

	it("issues once for one assertion sent to two instances at once, the later take finding its challenge taken [guarantee-5-h] {fault:H2}", async () => {
		await on({ name: "passkey-challenge-once-h2", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			const authenticator = await registeredAt(a);
			await control(a, authenticator);
			const sent = await assertionAt(a, authenticator);
			// Both have read the challenge open and are about to take it.
			const [heldA, heldB] = [
				a.relay.hold(takeOf(sent.challenge)),
				b.relay.hold(takeOf(sent.challenge)),
			];
			const [atA, atB] = [useAt(a, sent), useAt(b, sent)];
			const [first, second] = await Promise.all([heldA, heldB]);
			first.release();
			const earlier = await atA;
			expect(earlier.answer && said(earlier.answer)).toEqual(issued);
			second.release();
			const later = await atB;
			refusedAsUsed(later);
			await usedOnce([earlier, later, await useAt(b, sent)], 1, b, authenticator);
		});
	});

	it("issues at most once for one assertion whose two takes at two instances are let go together [guarantee-5-h] {fault:H2}", async () => {
		await on({ name: "passkey-challenge-once-h2-together", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			const authenticator = await registeredAt(a);
			await control(a, authenticator);
			const sent = await assertionAt(a, authenticator);
			const holds = [a.relay.hold(takeOf(sent.challenge)), b.relay.hold(takeOf(sent.challenge))];
			const both = Promise.all([useAt(a, sent), useAt(b, sent)]);
			for (const held of await Promise.all(holds)) held.release();
			const uses = [...(await both), await useAt(b, sent)];
			const tokens = issuedOver(uses);
			expect(tokens).toBeLessThanOrEqual(1);
			// Every use not issued is refused as its challenge not open, the two let go together among them.
			for (const u of uses.filter((u) => u.answer?.status !== 200)) refusedAsUsed(u);
			await usedOnce(uses, tokens, b, authenticator);
		});
	});
});
