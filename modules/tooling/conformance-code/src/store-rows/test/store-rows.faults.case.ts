import {
	confirmation,
	type Deployed,
	type Instance,
	instanceOf,
	isNoReplicas,
	isOutOfMemory,
	type Node,
	type Reply,
	ready,
	recovered,
	startDeployment,
	successes,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import { type Code, codeAt, faultScene, on, redeemAt, said } from "../../faults/test/faults.ts";
import { codeRecord, codeUse } from "../../faults/test/wire.ts";

const refused = [400, "invalid_grant"];
const issued = [200, "Bearer"];
const unavailable = [503, "temporarily_unavailable"];
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** The control: with no fault, a code is used up by one write that succeeds, and a token given. */
async function control(i: Instance) {
	const c = await codeAt(i);
	const seen = i.relay.observe(codeUse(c));
	expect(said(await redeemAt(i, c))).toEqual(issued);
	await seen;
}

/** Healed, the code the fault kept from being used is redeemed once. */
async function redeemedOnce(i: Instance, c: Code) {
	await ready(i);
	expect(said(await redeemAt(i, c))).toEqual(issued);
	expect(said(await redeemAt(i, c))).toEqual(refused);
}

/** The value of a field of the node's `INFO replication`. */
async function replicationField(n: Node, name: string) {
	const info = await n.ask("INFO", "replication");
	const text = info.kind === "bulk" ? (info.data?.toString() ?? "") : "";
	return new RegExp(`^${name}:(.*)$`, "m").exec(text)?.[1]?.trim();
}

/** Until the field reads `value`, within 30 s. */
async function until(n: Node, name: string, value: string) {
	const end = performance.now() + 30_000;
	while ((await replicationField(n, name)) !== value) {
		if (performance.now() > end) throw new Error(`${name} never read ${value}`);
		await pause(100);
	}
}

const ok = async (n: Node, ...args: string[]) => {
	const reply = await n.ask(...args);
	expect(reply.kind, args.join(" ")).not.toBe("error");
};

/** The first failed answer to a code's write that the predicate takes, after the fault began. */
const refusedWrite = (i: Instance, since: number, is: (reply: Reply) => boolean) =>
	i.relay.executions(codeRecord).find((e) => e.at > since && !e.succeeded && is(e.reply));

describe("nothing issued while the store cannot write, and a request after it can passes", () => {
	it("gives no token while Redis is out of its bounded memory, and redeems the code once after [guarantee-3-j] {fault:M}", async () => {
		await on({ name: "store-rows-m" }, async (d: Deployed) => {
			const a = instanceOf(d);
			await control(a);
			const c = await codeAt(a);
			const primary = d.topology.primary();
			const since = performance.now();
			// A bound below what Redis already holds: under noeviction, every write is refused.
			await ok(primary, "CONFIG", "SET", "maxmemory", "1");
			const answer = await redeemAt(a, c);
			await ok(primary, "CONFIG", "SET", "maxmemory", "0");
			expect(said(answer)).toEqual(unavailable);
			expect(answer.body.access_token).toBeUndefined();
			expect(refusedWrite(a, since, isOutOfMemory)).toBeDefined();
			expect(successes(a, codeUse(c))).toEqual([]);
			await redeemedOnce(a, c);
		});
	});

	it("starts with no replica under replication replicas, gives no token, and redeems the code once a replica follows [guarantee-3-j] {fault:R0}", async () => {
		await on({ name: "store-rows-r0", replicas: 1 }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const c = await codeAt(a);
			const primary = d.topology.primary();
			const [replica] = d.topology.replicas();
			if (!replica) throw new Error("a replica");
			// The replica stops following: the primary has none, though replication stays replicas.
			await ok(replica, "REPLICAOF", "NO", "ONE");
			await until(primary, "connected_slaves", "0");
			const since = performance.now();
			const answer = await redeemAt(a, c);
			expect(said(answer)).toEqual(unavailable);
			expect(answer.body.access_token).toBeUndefined();
			// Its confirmation found no replica to confirm with, or Redis refused the write for want of one.
			const roles = a.relay
				.executions({ request: (x) => x.name === "ROLE", succeeded: () => true })
				.filter((e) => e.at > since);
			const listed = (r: Reply) => (r.kind === "array" ? r.items?.[2] : undefined);
			const none = roles.some((e) => {
				const replicas = listed(e.reply);
				return replicas?.kind === "array" && replicas.items?.length === 0;
			});
			expect(none || refusedWrite(a, since, isNoReplicas) !== undefined).toBe(true);
			expect(successes(a, codeUse(c))).toEqual([]);
			await ok(replica, "REPLICAOF", primary.name, "6379");
			await recovered(d);
			await redeemedOnce(a, c);
		});
	});

	it("gives no token when a write's confirmation by the replicas times out, and redeems the code once after [guarantee-3-j] {fault:Wt}", async () => {
		// The scene's values, not the defaults. A confirmation waits 300 ms, so the resends' waits keep
		// the scene from growing too long.
		const redis = { "replication-timeout": "300ms" };
		// repl-timeout past the scene: a primary that dropped the stopped replica would confirm with WAIT 1.
		const settings = ["--repl-timeout", "300"];
		await on({ name: "store-rows-wt", settings, redis }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const c = await codeAt(a);
			const [paused] = d.topology.replicas();
			if (!paused) throw new Error("two replicas");
			// One of two replicas stops: the other still lets the primary write, but no write is
			// confirmed by both.
			d.topology.pause(paused, true);
			const short = a.relay.observe(confirmation({ replicas: 2 }), { outcome: "failed" });
			const since = performance.now();
			const answer = await redeemAt(a, c);
			d.topology.pause(paused, false);
			expect(said(answer)).toEqual(unavailable);
			expect(answer.body.access_token).toBeUndefined();
			await short;
			// Its first write on the code's record ran but was never confirmed, so the redemption stopped
			// there, before the code was used.
			expect(successes(a, codeRecord).some((e) => e.at > since)).toBe(true);
			expect(successes(a, codeUse(c))).toEqual([]);
			await recovered(d);
			await redeemedOnce(a, c);
		});
	});

	it("gives no token while Redis refuses writes as NOREPLICAS, and redeems the code once after [guarantee-3-j] {fault:Nr}", async () => {
		await on({ name: "store-rows-nr" }, async (d) => {
			const a = instanceOf(d);
			await control(a);
			const c = await codeAt(a);
			const primary = d.topology.primary();
			const replicas = d.topology.replicas();
			for (const r of replicas) d.topology.pause(r, true);
			// Past min-replicas-max-lag, the primary counts no good replica and refuses writes.
			await until(primary, "min_slaves_good_slaves", "0");
			const since = performance.now();
			const answer = await redeemAt(a, c);
			for (const r of replicas) d.topology.pause(r, false);
			expect(said(answer)).toEqual(unavailable);
			expect(answer.body.access_token).toBeUndefined();
			expect(refusedWrite(a, since, isNoReplicas)).toBeDefined();
			expect(successes(a, codeUse(c))).toEqual([]);
			await recovered(d);
			await redeemedOnce(a, c);
		});
	});

	it("refuses to boot on a Redis set to evict keys, where one set not to boots [guarantee-3-k] {fault:Ev}", async () => {
		await on({ name: "store-rows-ev" }, async (d) => {
			const a = instanceOf(d);
			// The control: the deployment booted on noeviction, and serves.
			await control(a);
			for (const n of [d.topology.primary(), ...d.topology.replicas()])
				await ok(n, "CONFIG", "SET", "maxmemory-policy", "allkeys-lru");
			await expect(
				startDeployment({
					name: "store-rows-ev-evicting",
					scene: faultScene(),
					topology: d.topology,
					instances: 1,
				}),
			).rejects.toThrow(/maxmemory-policy/);
		});
	});
});
