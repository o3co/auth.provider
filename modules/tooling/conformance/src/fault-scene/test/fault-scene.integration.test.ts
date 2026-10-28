import { describe, expect, it } from "vitest";
import { area, type NewPart, onNew, sceneOf } from "../../areas.ts";
import type { Node } from "../../faults/topology.ts";
import type { Match } from "../../relay/relay.ts";
import {
	failover,
	instanceOf,
	on,
	ready,
	reconnected,
	recovered,
	replicasOnline,
	successes,
} from "../fault-scene.ts";

// A scene of no feature: the base's own modules on the Redis store.
const probe = area<NewPart>("fault-scene-probe");
onNew(probe, (part) => part);
const scene = sceneOf(probe.part({ store: "pausable" }));
const script: Match = { request: (c) => c.name === "EVAL", succeeded: () => true };

describe("a fault scene's deployment", () => {
	it("deploys on a topology of its own, ready, and stops both however the scene ends", async () => {
		let primary: Node | undefined;
		await expect(
			on({ name: "fault-scene-own", scene }, async (d) => {
				const a = instanceOf(d);
				await ready(a);
				expect(d.topology.replicas()).toHaveLength(2);
				expect(successes(a, script).length).toBeGreaterThan(0);
				expect(() => instanceOf(d, 1)).toThrow(/no instance 1/);
				primary = d.topology.primary();
				throw new Error("the scene failed");
			}),
		).rejects.toThrow("the scene failed");
		// The topology went with the deployment: its node's container is no longer there.
		expect(() => primary?.state()).toThrow();
	});

	it("promotes a replica that caught up, points the relay at it, and waits for its replicas", async () => {
		await on({ name: "fault-scene-failover", scene }, async (d) => {
			const a = instanceOf(d);
			await ready(a);
			const before = await d.topology.primary().runId();
			await failover(d);
			const primary = d.topology.primary();
			expect(await primary.runId()).not.toBe(before);
			await reconnected(a, primary.upstream());
			await replicasOnline(d);
			await ready(a);
		});
	});

	it("waits, after the primary slept, until it takes writes again", async () => {
		await on({ name: "fault-scene-recovered", scene }, async (d) => {
			const primary = d.topology.primary();
			const { asleep, awake } = d.topology.sleep(primary, 5);
			await asleep;
			await awake;
			await recovered(d);
			// Recovered, a write is taken: no NOREPLICAS for want of good replicas.
			expect(await primary.ask("SET", "fault-scene-recovered", "1")).toEqual({
				kind: "simple",
				text: "OK",
			});
		});
	});

	it("fails past its bound naming what it waited on, while no replica acknowledges", async () => {
		await on({ name: "fault-scene-unrecovered", scene }, async (d) => {
			const replicas = d.topology.replicas();
			for (const r of replicas) d.topology.pause(r, true);
			try {
				// Their last acknowledgements age past the topology's max lag (2 s): none is good.
				const end = performance.now() + 10_000;
				for (;;) {
					const info = await d.topology.primary().ask("INFO", "replication");
					const text = info.kind === "bulk" ? (info.data?.toString() ?? "") : "";
					if (/min_slaves_good_slaves:0\b/.test(text)) break;
					if (performance.now() > end) throw new Error("the paused replicas stayed good");
					await new Promise((resolve) => setTimeout(resolve, 100));
				}
				await expect(recovered(d)).rejects.toThrow(
					/not recovered within 30 s: .*min_slaves_good_slaves 0 of the 1 min-replicas-to-write asks/,
				);
			} finally {
				for (const r of replicas) d.topology.pause(r, false);
			}
		});
	}, 120_000);

	it("hands a scene no deployment whose primary refuses writes, failing at the start naming what it waited on", async () => {
		let entered = false;
		// One replica where two are asked: the primary never counts the good replicas a write needs.
		const unwritable = { replicas: 1, settings: ["--min-replicas-to-write", "2"] };
		await expect(
			on({ name: "fault-scene-unwritable", scene, ...unwritable }, async () => {
				entered = true;
			}),
		).rejects.toThrow(/min_slaves_good_slaves 1 of the 2 min-replicas-to-write asks/);
		expect(entered).toBe(false);
	}, 120_000);

	it("waits, after a promotion that keeps the old primary, until the client has checked its new connection and the new primary takes writes", async () => {
		await on({ name: "fault-scene-reconnected", scene, replicas: 3 }, async (d) => {
			const a = instanceOf(d);
			const [, moved, follower] = d.topology.replicas();
			if (!moved || !follower) throw new Error("three replicas");
			await d.topology.promote({ replica: moved, reattach: [follower], keepOld: true });
			const switched = performance.now();
			a.relay.switchUpstream(moved.upstream());
			a.relay.reset("operations");
			await reconnected(a, moved.upstream());
			const onMoved = (id: number) => {
				const to = a.relay.connections().find((c) => c.id === id)?.upstream;
				return to?.host === moved.upstream().host && to.port === moved.upstream().port;
			};
			// A call was answered on the new connection, and the new primary takes a write at once.
			expect(
				a.relay
					.executions({ request: () => true, succeeded: () => true })
					.some((e) => e.at > switched && onMoved(e.connection)),
			).toBe(true);
			expect(await moved.ask("SET", "fault-scene-reconnected", "1")).toEqual({
				kind: "simple",
				text: "OK",
			});
		});
	}, 120_000);
});
