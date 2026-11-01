import {
	confirmation,
	failover,
	faultRun,
	hostLibfaketime,
	type Instance,
	instanceOf,
	type Match,
	ready,
	reconnected,
	replicasOnline,
	repointed,
	runIdOf,
	sameMark,
	successes,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import { type Code, codeAt, on, oneWrite, redeemAt, said } from "../../faults/test/faults.ts";
import { codeNoted, codeRecord, codeUse, isStoreOperation } from "../../faults/test/wire.ts";

const refused = [400, "invalid_grant"];
/** Every request the relay passed. */
const anything: Match = { request: () => true, succeeded: () => true };
const issued = [200, "Bearer"];

/**
 * The control: with no fault, a code is used up by one write that succeeds, and coming again it is
 * refused with no such write; so the match a scene's fault takes is the code's real use.
 */
async function control(i: Instance) {
	const c = await codeAt(i);
	const use = codeUse(c);
	const seen = i.relay.observe(use);
	expect(said(await redeemAt(i, c))).toEqual(issued);
	await seen;
	expect(successes(i, use)).toHaveLength(1);
	expect(said(await redeemAt(i, c))).toEqual(refused);
	expect(successes(i, use)).toHaveLength(1);
}

/** After the fault: the code is refused as used, and a new one is redeemed. */
async function refusedAsUsed(i: Instance, c: Code) {
	expect(said(await redeemAt(i, c))).toEqual(refused);
	expect(said(await redeemAt(i, await codeAt(i)))).toEqual(issued);
}

/** Every success of the code's use is one send under one mark: the write took effect once. */
const onceUnder = (i: Instance, c: Code, first: { command: Parameters<typeof sameMark>[0] }) => {
	const effects = successes(i, codeUse(c));
	expect(effects.length).toBeGreaterThan(0);
	expect(effects.every((e) => sameMark(first.command, e.command))).toBe(true);
};

describe("an authorization code redeemed once under faults", () => {
	it("redeems a code once whose use's answer is lost once, the resend taking the first answer [guarantee-5-a] {fault:Lr}", async () => {
		await on({ name: "code-once-lr" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const c = await codeAt(a);
			const drop = a.relay.dropReplyTo(codeUse(c));
			const answer = await redeemAt(a, c);
			const dropped = await drop.first;
			// Nothing but the use was cut with its answer.
			expect(dropped.collateral.filter((x) => isStoreOperation(x.command))).toEqual([]);
			expect(said(answer)).toEqual(issued);
			// The dropped send, and a resend under its mark that took its answer.
			expect(successes(a, codeUse(c)).length).toBeGreaterThan(1);
			onceUnder(a, c, dropped);
			await refusedAsUsed(a, c);
		});
	});

	it("answers unavailable and issues nothing when every answer to a code's use is lost, the code then refused as used [guarantee-5-a] {fault:Lx}", async () => {
		await on({ name: "code-once-lx" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const c = await codeAt(a);
			const drop = a.relay.dropReplyTo(codeUse(c), { resends: sameMark });
			const answer = await redeemAt(a, c);
			const dropped = await drop.first;
			drop.end();
			expect(drop.resends.length).toBeGreaterThan(0);
			expect(said(answer)).toEqual([503, "temporarily_unavailable"]);
			expect(successes(a, codeNoted(c))).toEqual([]);
			onceUnder(a, c, dropped);
			await ready(a);
			await refusedAsUsed(a, c);
		});
	});

	it("refuses a code used before a caught-up replica is promoted [guarantee-5-a] {fault:F}", async () => {
		await on({ name: "code-once-f" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const c = await codeAt(a);
			expect(said(await redeemAt(a, c))).toEqual(issued);
			const before = await d.topology.primary().runId();
			await failover(d);
			expect(await d.topology.primary().runId()).not.toBe(before);
			await ready(a);
			await refusedAsUsed(a, c);
		});
	});

	it("never takes a code's record confirmed on a server other than the one that answered it [guarantee-5-a] {fault:Fs}", async () => {
		await on({ name: "code-once-fs", replicas: 3 }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const c = await codeAt(a);
			const old = d.topology.primary();
			const [, moved, follower] = d.topology.replicas();
			if (!moved || !follower) throw new Error("three replicas");
			// Two primaries, each with a replica of its own: the old one keeps the first.
			await d.topology.promote({ replica: moved, reattach: [follower], keepOld: true });
			const [oldId, newId] = [await old.runId(), await moved.runId()];
			expect(oldId).not.toBe(newId);
			a.relay.switchUpstream(moved.upstream());
			a.relay.reset("operations");
			// Sent once the app holds a connection to the new primary: before, it fails for want of one, a 503 that shows nothing.
			await reconnected(a, moved.upstream());
			const from = a.relay.executions(anything).length;
			const confirmed = a.relay.observe(confirmation({ replicas: 1 }));
			const answer = await redeemAt(a, c);
			const wait = await confirmed;
			const upstreamOf = (id: number) => a.relay.connections().find((x) => x.id === id)?.upstream;
			const sent = a.relay.executions(anything).slice(from);
			// The first write on the code's record ran on the new primary, on a connection to it ...
			const first = sent.find((e) => e.at < wait.at && codeRecord.request(e.command));
			expect(first && runIdOf(first.reply)).toBe(newId);
			expect(first && upstreamOf(first.connection)).toEqual(moved.upstream());
			// ... and its confirmation passed on the old one, on a connection still to it.
			expect(upstreamOf(wait.connection)).toEqual(old.upstream());
			const info = sent.findLast(
				(e) => e.connection === wait.connection && e.command.name === "INFO",
			);
			expect(info?.reply.kind === "bulk" && info.reply.data?.toString()).toContain(
				`run_id:${oldId}`,
			);
			// So only the comparison of the two run ids is left to refuse it, before the code is used.
			expect(said(answer)).toEqual([503, "temporarily_unavailable"]);
			expect(successes(a, codeUse(c))).toEqual([]);
			a.relay.reset("confirming");
			await ready(a);
			// Unused, it is redeemed once.
			expect(said(await redeemAt(a, c))).toEqual(issued);
			await refusedAsUsed(a, c);
		});
	});

	it("refuses a code used before Redis is killed at once and started again [guarantee-5-a] {fault:C}", async () => {
		await on({ name: "code-once-c" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const c = await codeAt(a);
			expect(said(await redeemAt(a, c))).toEqual(issued);
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			repointed(d);
			await replicasOnline(d);
			await ready(a);
			await refusedAsUsed(a, c);
		});
	});

	it("refuses, at another instance, a code whose instance was killed after using it up and before answering [guarantee-5-a] {fault:K}", async () => {
		await on({ name: "code-once-k", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const c = await codeAt(a);
			const used = a.relay.observe(codeUse(c));
			const held = a.relay.hold(codeNoted(c));
			const answer = redeemAt(a, c).catch(() => undefined);
			await used;
			await held;
			const ended = await a.kill();
			expect(ended.signal).toBe("SIGKILL");
			const cut = await answer;
			expect(cut?.body.access_token).toBeUndefined();
			expect(successes(a, codeUse(c))).toHaveLength(1);
			expect(a.relay.executions(codeNoted(c))).toEqual([]);
			await ready(b);
			await refusedAsUsed(b, c);
		});
	});

	it("issues once for one code sent to two instances at once, the later use losing the race [guarantee-5-a] {fault:H2}", async () => {
		await on({ name: "code-once-h2", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const c = await codeAt(a);
			// Both have read the code unused before either writes its use.
			const [heldA, heldB] = [a.relay.hold(codeUse(c)), b.relay.hold(codeUse(c))];
			const [atA, atB] = [redeemAt(a, c), redeemAt(b, c)];
			const [first, second] = await Promise.all([heldA, heldB]);
			// One answered before the other writes: a use that comes while a redemption runs voids it, as
			// a code that comes again does, so releasing both at once would leave none issued.
			first.release();
			expect(said(await atA)).toEqual(issued);
			second.release();
			expect(said(await atB)).toEqual(refused);
			// Both uses reached Redis on what they read; only the first took effect, b's never.
			oneWrite(a.relay.executions(codeUse(c)));
			oneWrite(b.relay.executions(codeUse(c)));
			expect(b.relay.executions(codeUse(c)).some((e) => e.succeeded)).toBe(false);
			expect(successes(a, codeUse(c)).length + successes(b, codeUse(c)).length).toBe(1);
			await refusedAsUsed(b, c);
		});
	});

	it("issues at most once for one code whose two uses at two instances are let go together, a use that comes mid-redemption voiding the code [guarantee-5-a] {fault:H2}", async () => {
		await on({ name: "code-once-h2-together", instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const c = await codeAt(a);
			const holds = [a.relay.hold(codeUse(c)), b.relay.hold(codeUse(c))];
			const answers = Promise.all([redeemAt(a, c), redeemAt(b, c)]);
			for (const held of await Promise.all(holds)) held.release();
			const both = (await answers).map(said);
			const tokens = both.filter((s) => s[0] === 200);
			expect(tokens.length).toBeLessThanOrEqual(1);
			// None issued only as a code that comes again is refused, and voided (RFC 6749 §4.1.2).
			if (tokens.length === 0) expect(both).toEqual([refused, refused]);
			expect(successes(a, codeUse(c)).length + successes(b, codeUse(c)).length).toBe(1);
			await refusedAsUsed(b, c);
		});
	});

	// Where the probe finds a libfaketime that moves Node's clock; a fault run never skips it.
	it.runIf(faultRun() || hostLibfaketime() !== undefined)(
		"redeems a code once at an instance whose clock is moved forward or back, its lifetime on Redis's clock [guarantee-5-a] {fault:Ta}",
		async () => {
			await on({ name: "code-once-ta", instances: 2 }, async (d) => {
				const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
				await control(a);
				// Twice the code's 10 minute lifetime, so an end on the app's clock would refuse it. Each
				// code is redeemed where the clock is ahead of the one that gave it, so its login is never
				// in the future there, which issuing refuses past 5 minutes.
				const rounds = [
					{ offset: "+20m", gives: a, redeems: b },
					{ offset: "-20m", gives: b, redeems: a },
				];
				for (const { offset, gives, redeems } of rounds) {
					await b.clock(offset);
					await ready(b);
					const c = await codeAt(gives);
					expect(said(await redeemAt(redeems, c)), offset).toEqual(issued);
					expect(said(await redeemAt(gives, c)), offset).toEqual(refused);
					expect(said(await redeemAt(redeems, c)), offset).toEqual(refused);
				}
			});
		},
	);
});
