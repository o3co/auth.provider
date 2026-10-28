import {
	confirmation,
	failover,
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
import { codeAt, faultScene, on, redeemAt, refreshAt, said } from "../../faults/test/faults.ts";
import { onFamilies, rotationFrom } from "../../faults/test/wire.ts";

const scene = faultScene({ refresh: {} });
const refused = [400, "invalid_grant"];
const issued = [200, "Bearer"];
/** Every request the relay passed. */
const anything: Match = { request: () => true, succeeded: () => true };

/** A family's first refresh token, from a code the instance gives and redeems. */
async function familyAt(i: Instance): Promise<string> {
	const answer = await redeemAt(i, await codeAt(i));
	const token = answer.body.refresh_token;
	if (typeof token !== "string") throw new Error(`no refresh token: ${answer.status}`);
	return token;
}

/** The refresh token an answer gave, which must have given one. */
const next = (answer: { body: Readonly<Record<string, unknown>> }) => {
	const token = answer.body.refresh_token;
	if (typeof token !== "string") throw new Error("the answer gave no refresh token");
	return token;
};

/**
 * The control: with no fault, a refresh token is rotated by one write that succeeds, and coming
 * again it is refused with no such write; so the match a scene's fault takes is the real rotation.
 */
async function control(i: Instance) {
	const token = await familyAt(i);
	const rotation = rotationFrom(token);
	const seen = i.relay.observe(rotation);
	expect(said(await refreshAt(i, token))).toEqual(issued);
	await seen;
	expect(successes(i, rotation)).toHaveLength(1);
	expect(said(await refreshAt(i, token))).toEqual(refused);
	expect(successes(i, rotation)).toHaveLength(1);
}

/** After the fault: the token is refused as spent, and a new family is rotated. */
async function refusedAsSpent(i: Instance, token: string) {
	expect(said(await refreshAt(i, token))).toEqual(refused);
	expect(said(await refreshAt(i, await familyAt(i)))).toEqual(issued);
}

describe("a refresh token rotated once under faults", () => {
	it("rotates a refresh token once whose rotation's answer is lost once, the resend taking the first answer [guarantee-5-b] {fault:Lr}", async () => {
		await on({ name: "refresh-once-lr", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const token = await familyAt(a);
			const drop = a.relay.dropReplyTo(rotationFrom(token));
			const answer = await refreshAt(a, token);
			const dropped = await drop.first;
			expect(dropped.collateral.filter((x) => x.command.name === "EVAL")).toEqual([]);
			expect(said(answer)).toEqual(issued);
			const effects = successes(a, rotationFrom(token));
			expect(effects.length).toBeGreaterThan(1);
			expect(effects.every((e) => sameMark(dropped.command, e.command))).toBe(true);
			// The token answered is the family's current one: the rotation took effect once.
			expect(said(await refreshAt(a, next(answer)))).toEqual(issued);
			await refusedAsSpent(a, token);
		});
	});

	it("answers unavailable and gives no token when every answer to a rotation is lost, the token then refused as spent [guarantee-5-b] {fault:Lx}", async () => {
		await on({ name: "refresh-once-lx", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const token = await familyAt(a);
			const drop = a.relay.dropReplyTo(rotationFrom(token), { resends: sameMark });
			const answer = await refreshAt(a, token);
			const dropped = await drop.first;
			drop.end();
			expect(drop.resends.length).toBeGreaterThan(0);
			expect(said(answer)).toEqual([503, "temporarily_unavailable"]);
			expect(answer.body.refresh_token).toBeUndefined();
			const effects = successes(a, rotationFrom(token));
			expect(effects.every((e) => sameMark(dropped.command, e.command))).toBe(true);
			await ready(a);
			await refusedAsSpent(a, token);
		});
	});

	it("takes the token a rotation gave before a caught-up replica is promoted, and refuses the one before it [guarantee-5-b] {fault:F}", async () => {
		await on({ name: "refresh-once-f", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const token = await familyAt(a);
			const answer = await refreshAt(a, token);
			expect(said(answer)).toEqual(issued);
			await failover(d);
			await ready(a);
			// Kept through the promotion: the rotation's token is the current one, and the one before is spent.
			expect(said(await refreshAt(a, next(answer)))).toEqual(issued);
			await refusedAsSpent(a, token);
		});
	});

	it("never takes a family's record confirmed on a server other than the one that answered it [guarantee-5-b] {fault:Fs}", async () => {
		await on({ name: "refresh-once-fs", scene, replicas: 3 }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const token = await familyAt(a);
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
			const answer = await refreshAt(a, token);
			const wait = await confirmed;
			const upstreamOf = (id: number) => a.relay.connections().find((x) => x.id === id)?.upstream;
			const sent = a.relay.executions(anything).slice(from);
			// The first call on the family's record ran on the new primary, on a connection to it ...
			const first = sent.find((e) => e.at < wait.at && onFamilies(e.command));
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
			// So only the comparison of the two run ids is left to refuse it, before the family rotates.
			expect(said(answer)).toEqual([503, "temporarily_unavailable"]);
			expect(successes(a, rotationFrom(token))).toEqual([]);
			a.relay.reset("confirming");
			await ready(a);
			// Unrotated, it is rotated once.
			expect(said(await refreshAt(a, token))).toEqual(issued);
			await refusedAsSpent(a, token);
		});
	});

	it("takes the token a rotation gave before Redis is killed at once and started again, and refuses the one before it [guarantee-5-b] {fault:C}", async () => {
		await on({ name: "refresh-once-c", scene }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const token = await familyAt(a);
			const answer = await refreshAt(a, token);
			expect(said(answer)).toEqual(issued);
			const crashed = await d.topology.crash(d.topology.primary());
			expect(crashed.exitCode).toBe(137);
			repointed(d);
			await replicasOnline(d);
			await ready(a);
			expect(said(await refreshAt(a, next(answer)))).toEqual(issued);
			await refusedAsSpent(a, token);
		});
	});

	it("refuses, at another instance, a token whose instance was killed after rotating it and before answering [guarantee-5-b] {fault:K}", async () => {
		await on({ name: "refresh-once-k", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const token = await familyAt(a);
			// The rotation's confirmation held once the rotation has run, before the instance can answer.
			let held: Promise<unknown> | undefined;
			const rotated = a.relay.observe(rotationFrom(token)).then((e) => {
				held = a.relay.hold(confirmation({ replicas: 1 }));
				return e;
			});
			const answer = refreshAt(a, token).catch(() => undefined);
			await rotated;
			await held;
			const ended = await a.kill();
			expect(ended.signal).toBe("SIGKILL");
			expect((await answer)?.body.refresh_token).toBeUndefined();
			expect(successes(a, rotationFrom(token))).toHaveLength(1);
			await ready(b);
			await refusedAsSpent(b, token);
		});
	});

	it("rotates once for one token sent to two instances at once, the later rotation losing the race as a reuse [guarantee-5-b] {fault:H2}", async () => {
		await on({ name: "refresh-once-h2", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const token = await familyAt(a);
			// Both have read the family at this token before either rotates it.
			const [heldA, heldB] = [a.relay.hold(rotationFrom(token)), b.relay.hold(rotationFrom(token))];
			const [atA, atB] = [refreshAt(a, token), refreshAt(b, token)];
			const [first, second] = await Promise.all([heldA, heldB]);
			first.release();
			const winner = await atA;
			expect(said(winner)).toEqual(issued);
			second.release();
			expect(said(await atB)).toEqual(refused);
			// Both rotations reached Redis on what they read; only the first took effect.
			expect(a.relay.executions(rotationFrom(token))).toHaveLength(1);
			expect(b.relay.executions(rotationFrom(token))).toHaveLength(1);
			expect(
				successes(a, rotationFrom(token)).length + successes(b, rotationFrom(token)).length,
			).toBe(1);
			// The loser of two uses is a reuse, which ends the family: the winner's token goes with it.
			expect(said(await refreshAt(a, next(winner)))).toEqual(refused);
			await refusedAsSpent(b, token);
		});
	});

	it("rotates at most once for one token whose two rotations at two instances are let go together, the family then ended as a reuse [guarantee-5-b] {fault:H2}", async () => {
		await on({ name: "refresh-once-h2-together", scene, instances: 2 }, async (d) => {
			const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
			await control(a);
			const token = await familyAt(a);
			const holds = [a.relay.hold(rotationFrom(token)), b.relay.hold(rotationFrom(token))];
			const answers = Promise.all([refreshAt(a, token), refreshAt(b, token)]);
			for (const held of await Promise.all(holds)) held.release();
			const both = await answers;
			const tokens = both.filter((x) => x.status === 200);
			expect(tokens.length).toBeLessThanOrEqual(1);
			// None given only as both are refused, the loser's use a reuse either way.
			if (tokens.length === 0) expect(both.map(said)).toEqual([refused, refused]);
			expect(
				successes(a, rotationFrom(token)).length + successes(b, rotationFrom(token)).length,
			).toBeLessThanOrEqual(1);
			// The loser of two uses ends the family: no token of it is taken any more.
			for (const given of [token, ...tokens.map(next)]) {
				expect(said(await refreshAt(a, given))).toEqual(refused);
				expect(said(await refreshAt(b, given))).toEqual(refused);
			}
			expect(said(await refreshAt(b, await familyAt(b)))).toEqual(issued);
		});
	});
});
