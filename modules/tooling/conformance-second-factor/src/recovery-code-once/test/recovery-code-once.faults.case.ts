import type { SentEvent } from "@mod/conformance";
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
	type Codes,
	enrolledAt,
	heldAt,
	movedTo,
	on,
	said,
	usedAt,
} from "../../faults/test/faults.ts";
import { isStoreCall, useOf } from "../../faults/test/wire.ts";

const letIn = [200, undefined];
// A used code is refused as a wrong one is: only the audit event's reason tells them apart.
const refused = [401, "mfa_invalid"];

/** Why the second factor refused, as the instance recorded it. */
const reasons = (events: readonly SentEvent[]) =>
	events.filter((e) => e.kind === "mfa.verify.failure").map((e) => e.attributes?.reason);

/**
 * Refused as used: the held login is refused, recorded `replayed` (a wrong code is `invalid`, a
 * race lost `raced`), with no write of the code's use sent; and a new code lets the same login in.
 */
async function refusedAsUsed(i: Instance, codes: Codes, code: string) {
	const { b, transaction } = await heldAt(i);
	const sent = i.relay.executions(useOf(code)).length;
	const { result, events } = await i.audit.during(() => usedAt(b, transaction, code));
	expect(said(result)).toEqual(refused);
	expect(reasons(events)).toEqual(["replayed"]);
	expect(i.relay.executions(useOf(code))).toHaveLength(sent);
	expect(said(await usedAt(b, transaction, codes.next()))).toEqual(letIn);
}

/**
 * The control: with no fault, a recovery code is used up by one write that succeeds, and coming
 * again it is refused as used with no such write.
 */
async function control(i: Instance, codes: Codes) {
	const code = codes.next();
	const { b, transaction } = await heldAt(i);
	const seen = i.relay.observe(useOf(code));
	expect(said(await usedAt(b, transaction, code))).toEqual(letIn);
	await seen;
	expect(successes(i, useOf(code))).toHaveLength(1);
	await refusedAsUsed(i, codes, code);
	expect(successes(i, useOf(code))).toHaveLength(1);
}

/** Every success of the code's use is one send under one mark: it took effect once. */
const onceUnder = (
	i: Instance,
	code: string,
	first: { command: Parameters<typeof sameMark>[0] },
) => {
	const effects = successes(i, useOf(code));
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

describe("a recovery code used once under faults", () => {
	it("lets in once by a recovery code whose use's answer is lost once, the resend taking the first answer [guarantee-5-g] {fault:Lr}", async () => {
		await on({ name: "recovery-code-once-lr" }, async (d) => {
			const i = instanceOf(d);
			const codes = await enrolledAt(i);
			await control(i, codes);
			const code = codes.next();
			const { b, transaction } = await heldAt(i);
			const drop = i.relay.dropReplyTo(useOf(code));
			const answer = await usedAt(b, transaction, code);
			const dropped = await drop.first;
			// Nothing but the use was cut with its answer.
			expect(dropped.collateral.filter((x) => isStoreCall(x.command))).toEqual([]);
			expect(said(answer)).toEqual(letIn);
			expect(successes(i, useOf(code)).length).toBeGreaterThan(1);
			onceUnder(i, code, dropped);
			await refusedAsUsed(i, codes, code);
		});
	});

	it("answers unavailable and lets nothing in when every answer to a code's use is lost, the code then refused as used [guarantee-5-g] {fault:Lx}", async () => {
		await on({ name: "recovery-code-once-lx" }, async (d) => {
			const i = instanceOf(d);
			const codes = await enrolledAt(i);
			await control(i, codes);
			const code = codes.next();
			const { b, transaction } = await heldAt(i);
			const drop = i.relay.dropReplyTo(useOf(code), { resends: sameMark });
			const answer = await usedAt(b, transaction, code);
			const dropped = await drop.first;
			drop.end();
			expect(drop.resends.length).toBeGreaterThan(0);
			expect(answer.status).toBe(503);
			onceUnder(i, code, dropped);
			await ready(i);
			await refusedAsUsed(i, codes, code);
		});
	});

	it("refuses a recovery code used before a caught-up replica is promoted [guarantee-5-g] {fault:F}", async () => {
		await on({ name: "recovery-code-once-f" }, async (d) => {
			const i = instanceOf(d);
			const codes = await enrolledAt(i);
			await control(i, codes);
			const code = codes.next();
			const { b, transaction } = await heldAt(i);
			expect(said(await usedAt(b, transaction, code))).toEqual(letIn);
			const before = await d.topology.primary().runId();
			await failover(d);
			expect(await d.topology.primary().runId()).not.toBe(before);
			await ready(i);
			await refusedAsUsed(i, codes, code);
		});
	});

	it("refuses a recovery code used before Redis is killed at once and started again [guarantee-5-g] {fault:C}", async () => {
		await on({ name: "recovery-code-once-c" }, async (d) => {
			const i = instanceOf(d);
			const codes = await enrolledAt(i);
			await control(i, codes);
			const code = codes.next();
			const { b, transaction } = await heldAt(i);
			expect(said(await usedAt(b, transaction, code))).toEqual(letIn);
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			repointed(d);
			await replicasOnline(d);
			await ready(i);
			await refusedAsUsed(i, codes, code);
		});
	});

	it("refuses, at another instance, a recovery code whose instance was killed after using it up and before answering, the same login going on there [guarantee-5-g] {fault:K}", async () => {
		await on({ name: "recovery-code-once-k", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			const codes = await enrolledAt(a);
			await control(a, codes);
			const code = codes.next();
			const held = await heldAt(a);
			// The use's confirmation held once the use has run, before the instance can answer.
			let holding: Promise<unknown> | undefined;
			const used = a.relay.observe(useOf(code)).then((e) => {
				holding = a.relay.hold(confirmation({ replicas: 1 }));
				return e;
			});
			const answer = usedAt(held.b, held.transaction, code).catch(() => undefined);
			await used;
			await holding;
			const ended = await a.kill();
			expect(ended.signal).toBe("SIGKILL");
			expect((await answer)?.status).not.toBe(200);
			expect(successes(a, useOf(code))).toHaveLength(1);
			await ready(b);
			// The same held login, its browser now behind the other instance: the code is used.
			const moved = movedTo(b, held.b);
			const { result, events } = await b.audit.during(() => usedAt(moved, held.transaction, code));
			expect(said(result)).toEqual(refused);
			expect(reasons(events)).toEqual(["replayed"]);
			expect(b.relay.executions(useOf(code))).toEqual([]);
			expect(said(await usedAt(moved, held.transaction, codes.next()))).toEqual(letIn);
			await refusedAsUsed(b, codes, code);
		});
	});

	it("lets in once by one recovery code used at two instances at once, the later use losing the race [guarantee-5-g] {fault:H2}", async () => {
		await on({ name: "recovery-code-once-h2", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			const codes = await enrolledAt(a);
			await control(a, codes);
			const code = codes.next();
			const [atA, atB] = [await heldAt(a), await heldAt(b)];
			// Both have judged the code unused and are about to use it.
			const [heldA, heldB] = [a.relay.hold(useOf(code)), b.relay.hold(useOf(code))];
			const usingA = usedAt(atA.b, atA.transaction, code);
			const usingB = b.audit.during(() => usedAt(atB.b, atB.transaction, code));
			const [first, second] = await Promise.all([heldA, heldB]);
			first.release();
			expect(said(await usingA)).toEqual(letIn);
			second.release();
			const later = await usingB;
			expect(said(later.result)).toEqual(refused);
			expect(reasons(later.events)).toEqual(["raced"]);
			// The later use reached Redis on what it read and never took effect; only the first did.
			lostOnly(b, useOf(code));
			expect(successes(a, useOf(code)).length + successes(b, useOf(code)).length).toBe(1);
			await refusedAsUsed(b, codes, code);
		});
	});

	it("lets in at most once by one recovery code whose two uses at two instances are let go together [guarantee-5-g] {fault:H2}", async () => {
		await on({ name: "recovery-code-once-h2-together", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			const codes = await enrolledAt(a);
			await control(a, codes);
			const code = codes.next();
			const [atA, atB] = [await heldAt(a), await heldAt(b)];
			const holds = [a.relay.hold(useOf(code)), b.relay.hold(useOf(code))];
			const both = Promise.all([
				a.audit.during(() => usedAt(atA.b, atA.transaction, code)),
				b.audit.during(() => usedAt(atB.b, atB.transaction, code)),
			]);
			for (const held of await Promise.all(holds)) held.release();
			const answers = await both;
			expect(answers.filter((x) => x.result.status === 200).length).toBeLessThanOrEqual(1);
			// One use takes effect; the other finds the list moved on and is refused as a race lost.
			expect(successes(a, useOf(code)).length + successes(b, useOf(code)).length).toBe(1);
			for (const lost of answers.filter((x) => x.result.status !== 200)) {
				expect(said(lost.result)).toEqual(refused);
				expect(reasons(lost.events)).toEqual(["raced"]);
			}
			await refusedAsUsed(b, codes, code);
		});
	});
});
