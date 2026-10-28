import {
	faultRun,
	hostLibfaketime,
	type Instance,
	instanceOf,
	type Node,
	ready,
	replicasOnline,
	storeWrite,
	successes,
} from "@mod/conformance/testing";
import { describe, expect, it } from "vitest";
import {
	codeAt,
	codeUse,
	faultScene,
	on,
	prefix,
	redeemAt,
	said,
} from "../../faults/test/faults.ts";
import { backChannel } from "../../testing.ts";

// Bounds the security model leaves to the operator, recorded as they are: no promise is checked
// here, so no scene names a guarantee or a fault of one.

const issued = [200, "Bearer"];
const refused = [400, "invalid_grant"];
/** The write that keeps a new code: the record a code is issued with. */
const codeKept = storeWrite({
	prefix,
	space: "code-grant-store.codes",
	operations: ["putIfAbsent"],
});
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const ok = async (n: Node, ...args: string[]) => {
	const reply = await n.ask(...args);
	expect(reply.kind, args.join(" ")).not.toBe("error");
	return reply;
};
/** The node's `INFO replication`, as text. */
const replicationOf = async (n: Node) => {
	const reply = await n.ask("INFO", "replication");
	return reply.kind === "bulk" ? (reply.data?.toString() ?? "") : "";
};
const numberOf = (reply: Awaited<ReturnType<Node["ask"]>>) =>
	reply.kind === "integer" ? reply.value : Number.NaN;

describe("bounds the operator keeps", () => {
	it("keeps a code its lifetime on Redis's clock, moved two hours ahead of the app's", async ({
		annotate,
	}) => {
		await on({ name: "boundaries-redis-clock", clock: "+2h" }, async (d) => {
			const a = instanceOf(d);
			const primary = d.topology.primary();
			// Redis's clock runs two hours ahead of this host's, which the app runs on.
			const time = await ok(primary, "TIME");
			const seconds =
				time.kind === "array" && time.items?.[0]?.kind === "bulk"
					? Number(time.items[0].data?.toString())
					: Number.NaN;
			const ahead = seconds - Date.now() / 1000;
			expect(ahead).toBeGreaterThan(7_100);
			expect(ahead).toBeLessThan(7_300);
			const since = successes(a, codeKept).length;
			const c = await codeAt(a);
			// Its record lives the code's 10 minutes counted on Redis's clock, whatever the app's reads.
			const [kept] = successes(a, codeKept).slice(since);
			const key = kept?.command.args[2]?.toString() ?? "";
			const left = numberOf(await ok(primary, "PTTL", key));
			expect(left).toBeGreaterThan(9 * 60_000);
			expect(left).toBeLessThanOrEqual(10 * 60_000 + 1_000);
			expect(said(await redeemAt(a, c))).toEqual(issued);
			expect(said(await redeemAt(a, c))).toEqual(refused);
			await annotate(
				`Redis ${Math.round(ahead)} s ahead; a code's record lives ${left} ms on its clock`,
			);
		});
	});

	it("loses a confirmed use where a replica that fell behind is promoted unchecked, the code taken again", async ({
		annotate,
	}) => {
		await on({ name: "boundaries-lagging-promotion" }, async (d) => {
			const a = instanceOf(d);
			const old = d.topology.primary();
			const [follower, behind] = d.topology.replicas();
			if (!follower || !behind) throw new Error("two replicas");
			const c = await codeAt(a);
			// One replica stops following: what comes after, the code's use among it, is confirmed by
			// the other alone.
			await ok(behind, "REPLICAOF", "NO", "ONE");
			expect(said(await redeemAt(a, c))).toEqual(issued);
			expect(successes(a, codeUse(c))).toHaveLength(1);
			// The operator promotes the one that fell behind, checking nothing, and the old primary is gone.
			d.topology.pause(old, true);
			await ok(follower, "REPLICAOF", behind.name, "6379");
			const end = performance.now() + 30_000;
			// Online, as replicasOnline counts them: a replica still syncing is connected but takes no write.
			while (!/^slave\d+:.*state=online/m.test(await replicationOf(behind))) {
				if (performance.now() > end) throw new Error("the follower did not follow");
				await pause(100);
			}
			a.relay.switchUpstream(behind.upstream());
			a.relay.reset("all");
			await ready(a);
			// The use it never received is gone: the same code is taken again.
			const again = said(await redeemAt(a, c));
			expect(again).toEqual(issued);
			await annotate(
				"a confirmed use lost: the code was redeemed again after the unchecked promotion",
			);
		});
	});

	// Where the probe finds a libfaketime that moves Node's clock; a fault run never skips it.
	it.runIf(faultRun() || hostLibfaketime() !== undefined)(
		"decides a token's expiry on each instance's own clock, so instances whose clocks part decide it apart",
		async ({ annotate }) => {
			await on(
				{ name: "boundaries-app-clocks", scene: faultScene({ userinfo: true }), instances: 2 },
				async (d) => {
					const [a, b] = [instanceOf(d, 0), instanceOf(d, 1)];
					await b.clock("+2h");
					await ready(b);
					await replicasOnline(d);
					const token = (await redeemAt(a, await codeAt(a))).body.access_token as string;
					const at = (i: Instance) =>
						fetch(`${i.baseUrl}/oauth/userinfo`, {
							headers: { ...backChannel, authorization: `Bearer ${token}` },
						}).then((r) => r.status);
					// Within its hour on the first's clock; past it on the second's.
					expect(await at(a)).toBe(200);
					expect(await at(b)).toBe(401);
					await annotate(
						"a token taken where it was issued is refused where the clock runs two hours ahead",
					);
				},
			);
		},
	);
});
