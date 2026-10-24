import { testRequest } from "@mod/http/testing";
import { BootRefused, defineModule, type Probe, probes } from "@mod/kernel";
import { quietLog, quietRuntime } from "@mod/kernel/testing";
import { metrics } from "@mod/metrics";
import metricsModule from "@mod/metrics/module";
import { afterEach, describe, expect, it } from "vitest";
import { readyz as readyzRoute, sharedReadiness } from "../src/readiness.ts";
import { section } from "../src/section.ts";
import { assembled } from "./harness.ts";

let now = 0;
const warned: string[] = [];
const quiet = quietRuntime({
	clock: { now: () => now },
	random: { bytes: (n) => new Uint8Array(n) },
	log: {
		...quietLog,
		warn: (event) => {
			warned.push(event);
		},
	},
});

afterEach(() => {
	now = 0;
	warned.length = 0;
});

const probeModule = (probe: Probe) =>
	defineModule({ name: `probe-${probe.name}`, takes: [] }, (m) => [
		m.contribute(probes).by(() => probe),
	]);

function boot(probe: Probe, settings: Record<string, unknown> = {}) {
	return assembled([probeModule(probe)], quiet, settings);
}

/** Boots with this probe and asks `/readyz` once; `again` asks it more. */
async function readyz(probe: Probe, settings: Record<string, unknown> = {}) {
	const { get } = await boot(probe, settings);
	const again = async () => (await get("/readyz")).status;
	const res = await get("/readyz");
	return { status: res.status, headers: res.headers, body: res.body, again };
}

const after = (ms: number): Probe => ({
	name: "store",
	check: (signal) =>
		new Promise<void>((resolve, reject) => {
			const timer = setTimeout(resolve, ms);
			signal.addEventListener("abort", () => {
				clearTimeout(timer);
				reject(new Error("aborted"));
			});
		}),
});

const noStore = { "cache-control": "no-store", pragma: "no-cache" };

describe("readyz", () => {
	it("answers 200 and ready when the probes pass, never to be cached", async () => {
		expect(await readyz({ name: "store", check: async () => {} })).toMatchObject({
			status: 200,
			headers: noStore,
			body: { json: { status: "ready" } },
		});
	});

	it("answers 503 and unready when a probe fails, saying nothing of what failed", async () => {
		const down: Probe = {
			name: "store",
			check: async () => {
				throw new Error("connect ECONNREFUSED 10.0.0.7:6379");
			},
		};
		expect(await readyz(down)).toMatchObject({
			status: 503,
			headers: noStore,
			body: { json: { status: "unready" } },
		});
	});

	it("waits for the probes as long as readiness-deadline says, 1s unless set", async () => {
		expect((await readyz(after(200), { "readiness-deadline": "50ms" })).status).toBe(503);
		expect((await readyz(after(200))).status).toBe(200);
		expect((await readyz(after(1500))).status).toBe(503);
		expect(section.parse({})["readiness-deadline"]).toBe(1000);
	});

	it("refuses at boot a deadline without its unit, or not whole ms from 1 to 2^31-1", async () => {
		for (const bad of ["0ms", "1.5ms", `${2 ** 31}ms`, 1000, "1000"]) {
			const refused = await boot(after(0), { "readiness-deadline": bad }).catch((e) => e);
			expect(refused).toBeInstanceOf(BootRefused);
			expect((refused as BootRefused).refusals.map((r) => r.where)).toEqual([
				"http-ops.readiness-deadline",
			]);
		}
	});

	it("shares one probe run among requests, and reuses its answer for 1 s from when it started", async () => {
		let checks = 0;
		const counted: Probe = {
			name: "store",
			check: async () => {
				checks++;
				now += 900;
				await new Promise((r) => setTimeout(r, 50));
				throw new Error("down");
			},
		};
		const { get } = await boot(counted);
		const status = async () => (await get("/readyz")).status;
		const both = () => Promise.all([status(), status()]);
		expect([await both(), checks, warned.length]).toEqual([[503, 503], 1, 1]);
		now = 1000;
		expect([await both(), checks, warned.length]).toEqual([[503, 503], 2, 2]);
		// The run that started at 1000 ended at 1900: 1 s counts from its start.
		now = 1999;
		expect([await status(), checks]).toEqual([503, 2]);
		now = 2000;
		expect([await status(), checks]).toEqual([503, 3]);
	});

	it("joins a run still in flight however long it takes, and starts a new one when the clock is set back", async () => {
		const slow: Probe = {
			name: "store",
			check: async () => {
				now += 1500;
				await new Promise((r) => setTimeout(r, 50));
				throw new Error("down");
			},
		};
		const { get } = await boot(slow);
		now = 5000;
		await Promise.all([get("/readyz"), get("/readyz")]);
		expect(warned).toHaveLength(1);
		now = 4000;
		await get("/readyz");
		expect(warned).toHaveLength(2);
	});

	it("reuses no ready answer, so a failure shows at the next request", async () => {
		let up = true;
		const flaky: Probe = {
			name: "store",
			check: async () => {
				if (!up) throw new Error("down");
			},
		};
		const { status, again } = await readyz(flaky);
		expect(status).toBe(200);
		up = false;
		expect(await again()).toBe(503);
	});

	it("holds a readiness that failed to answer like an unready one, reused for 1 s and run again after", async () => {
		let calls = 0;
		let at = 0;
		const route = readyzRoute(
			sharedReadiness(
				async () => {
					calls++;
					throw new Error("no answer");
				},
				1000,
				{ now: () => at },
			),
		);
		await expect(route.handle(testRequest())).rejects.toThrow();
		at = 999;
		await expect(route.handle(testRequest())).rejects.toThrow();
		expect(calls).toBe(1);
		at = 1000;
		await expect(route.handle(testRequest())).rejects.toThrow();
		expect(calls).toBe(2);
	});
});

describe("the dependency-up gauge", () => {
	async function scraped(list: readonly Probe[]) {
		const { app, get } = await assembled([metricsModule, ...list.map(probeModule)], quiet);
		const gauge = async () =>
			(await app.get(metrics).sample()).find((r) => r.name === "auth_dependency_up");
		return { app, get, gauge };
	}

	it("gives 1 or 0 for each probe by its own name, with legacy's name, label and help", async () => {
		const { gauge } = await scraped([
			{ name: "store", check: async () => {} },
			{
				name: "cache",
				check: async () => {
					throw new Error("down at 10.0.0.7");
				},
			},
		]);
		expect(await gauge()).toEqual({
			kind: "gauge",
			name: "auth_dependency_up",
			help: "1 when a backing dependency answered its readiness probe, 0 otherwise.",
			labels: ["dependency"],
			series: [
				{ labels: { dependency: "store" }, value: 1 },
				{ labels: { dependency: "cache" }, value: 0 },
			],
		});
	});

	it("has no series before a scrape reads it", async () => {
		const { app } = await scraped([{ name: "store", check: async () => {} }]);
		const read = app
			.get(metrics)
			.read()
			.find((r) => r.name === "auth_dependency_up");
		expect(read?.series).toEqual([]);
	});

	it("joins the run /readyz has in flight, and reuses its unready result as /readyz does", async () => {
		let checks = 0;
		const { get, gauge } = await scraped([
			{
				name: "store",
				check: async () => {
					checks++;
					await new Promise((r) => setTimeout(r, 50));
					throw new Error("down");
				},
			},
		]);
		const [answer, read] = await Promise.all([get("/readyz"), gauge()]);
		expect([answer.status, read?.series, checks]).toEqual([
			503,
			[{ labels: { dependency: "store" }, value: 0 }],
			1,
		]);
		now = 999;
		expect([(await gauge())?.series.length, checks]).toEqual([1, 1]);
	});

	it("runs readiness at a scrape when no run is shared, never reusing a ready one", async () => {
		let checks = 0;
		const { gauge } = await scraped([{ name: "store", check: async () => void checks++ }]);
		await gauge();
		await gauge();
		expect(checks).toBe(2);
	});

	it("declares no label and gives no series with no probes", async () => {
		const { gauge } = await scraped([]);
		expect(await gauge()).toMatchObject({ labels: [], series: [] });
	});
});
