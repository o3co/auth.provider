import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { area, type NewPart, onNew, sceneOf } from "../../areas.ts";
import { hostLibfaketime } from "../../clock/clock.ts";
import { startTopology, type Topology } from "../../faults/topology.ts";
import type { Match } from "../../relay/relay.ts";
import { startDeployment } from "../deployment.ts";

// A scene of no feature: the base's own modules on the Redis store.
const probe = area<NewPart>("deployment-probe");
onNew(probe, (part) => part);
const scene = sceneOf(probe.part({ store: "pausable" }));
const script: Match = { request: (c) => c.name === "EVAL", succeeded: () => true };

let topology: Topology;
beforeAll(async () => {
	topology = await startTopology({ replicas: 0 });
});
afterAll(async () => {
	await topology?.stop();
});

describe("a deployment of a scene", () => {
	it("runs its instances on one Redis, each behind a relay and a trace of its own", async () => {
		const d = await startDeployment({ name: "two", scene, topology, instances: 2 });
		try {
			const [a, b] = d.instances;
			if (!a || !b) throw new Error("two instances");
			expect(a.baseUrl).not.toBe(b.baseUrl);
			await fetch(`${a.baseUrl}/a`);
			await fetch(`${b.baseUrl}/b`);
			expect(a.requests().map((r) => r.path)).toEqual(["/a"]);
			expect(b.requests().map((r) => r.path)).toEqual(["/b"]);
			for (const i of d.instances) {
				expect(i.relay.executions(script).length).toBeGreaterThan(0);
				expect(i.relay.connections()[0]?.upstream).toEqual(topology.primary().upstream());
			}
			expect(d.record.instances).toBe(2);
			// The probe's scene publishes no metadata: its instances are alike in that.
			expect(d.record.identity).toBeNull();
			expect(d.record.deployment).toBe("multi");
			expect(new Set(d.record.settings).size).toBe(1);
		} finally {
			await d.stop();
		}
	});

	it("kills an instance with SIGKILL and starts it again behind the same URL", async () => {
		const d = await startDeployment({ name: "kill", scene, topology, instances: 1 });
		try {
			const [a] = d.instances;
			if (!a) throw new Error("one instance");
			await fetch(`${a.baseUrl}/before`);
			const before = performance.now();
			const ended = await a.kill();
			// When it ended, on the clock the relay times what it saw by.
			expect(ended.signal).toBe("SIGKILL");
			expect(ended.endedAt).toBeGreaterThanOrEqual(before);
			expect(ended.endedAt).toBeLessThanOrEqual(performance.now());
			expect(a.running()).toBe(false);
			expect((await fetch(`${a.baseUrl}/down`)).status).toBe(502);
			await a.restart();
			expect(a.running()).toBe(true);
			expect((await fetch(`${a.baseUrl}/after`)).status).not.toBe(502);
			expect(a.requests().map((r) => r.path)).toEqual(["/before", "/down", "/after"]);
		} finally {
			await d.stop();
		}
	});

	it("writes the scene's set-up beside the run's reports", async () => {
		const dir = await mkdtemp(join(tmpdir(), "conformance-faults-"));
		const d = await startDeployment({
			name: "recorded",
			scene,
			topology,
			instances: 1,
			redis: { "command-timeout": "2s" },
			recordTo: dir,
		});
		await d.stop();
		const record = JSON.parse(await readFile(join(dir, "recorded.json"), "utf8"));
		expect(record).toMatchObject({
			name: "recorded",
			image: expect.stringMatching(/^redis:7\.4-alpine@sha256:/),
			replicas: 0,
			instances: 1,
			deployment: "single",
			relays: true,
			redis: { replication: "none", "command-timeout": "2s" },
		});
		expect(record.redis.url).toBeUndefined();
	});

	it.runIf(hostLibfaketime())(
		"moves an instance's clock, restarting it, and leaves the others' alone",
		async () => {
			const d = await startDeployment({ name: "clock", scene, topology, instances: 2 });
			try {
				const [a, b] = d.instances;
				if (!a || !b) throw new Error("two instances");
				await a.clock("+2h");
				const dateOf = async (url: string) =>
					Date.parse((await fetch(url)).headers.get("date") ?? "");
				const now = Date.now();
				expect(Math.abs((await dateOf(`${a.baseUrl}/`)) - (now + 7_200_000))).toBeLessThan(3000);
				expect(Math.abs((await dateOf(`${b.baseUrl}/`)) - now)).toBeLessThan(3000);
				expect(d.record.clocks).toEqual(["+2h", null]);
			} finally {
				await d.stop();
			}
		},
	);

	it.runIf(!hostLibfaketime())(
		"refuses to move a clock where this host has no thread-safe libfaketime",
		async () => {
			const d = await startDeployment({ name: "no-clock", scene, topology, instances: 1 });
			try {
				await expect(d.instances[0]?.clock("+2h")).rejects.toThrow(/libfaketime/);
			} finally {
				await d.stop();
			}
		},
	);

	it("fails its stop where a relay was asked for a fault that never happened", async () => {
		const d = await startDeployment({ name: "unfired", scene, topology, instances: 1 });
		d.instances[0]?.relay.dropReplyTo({ request: () => false, succeeded: () => true });
		await expect(d.stop()).rejects.toThrow(/never happened/);
	});
});
