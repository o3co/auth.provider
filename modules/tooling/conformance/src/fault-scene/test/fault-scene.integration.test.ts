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
});
