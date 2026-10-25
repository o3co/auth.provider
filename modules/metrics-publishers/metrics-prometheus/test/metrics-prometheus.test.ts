import { listening } from "@mod/http";
import http from "@mod/http/module";
import { assemble, BootRefused, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { counter, gauge, histogram, type Instrument, instruments } from "@mod/metrics";
import metricsModule from "@mod/metrics/module";
import { afterEach, describe, expect, it } from "vitest";
import prometheus from "../src/module.ts";
import { section } from "../src/section.ts";

const quiet = quietRuntime({
	clock: { now: () => 0 },
	random: { bytes: (n) => new Uint8Array(n) },
});

let stops: (() => Promise<void>)[] = [];
afterEach(async () => {
	for (const stop of stops) await stop();
	stops = [];
});

const boot = (modules: Module[], settings?: Record<string, unknown>) =>
	assemble({
		modules,
		config: {
			...kernelConfig(),
			http: { port: 0 },
			...(settings ? { "metrics-prometheus": settings } : {}),
		},
		runtime: quiet,
	});

async function serve(settings?: Record<string, unknown>, ...more: Module[]) {
	const app = await boot([http, metricsModule, prometheus, ...more], settings);
	await app.start();
	stops.push(() => app.stop(1000));
	return `http://127.0.0.1:${app.get(listening).port()}`;
}

async function refusals(modules: Module[], settings?: Record<string, unknown>) {
	const error = await boot(modules, settings).catch((e: unknown) => e);
	expect(error).toBeInstanceOf(BootRefused);
	return (error as BootRefused).refusals.map((r) => `${r.where}: ${r.reason}`);
}

const emitting = (...made: (() => Instrument)[]) =>
	defineModule({ name: "emitter", takes: [] }, (m) =>
		made.map((make) => m.contribute(instruments).by(make)),
	);

describe("scrape", () => {
	it("answers metrics' series and the process's counts as text, never to be cached", async () => {
		const work = histogram({
			name: "work_seconds",
			help: "Work.",
			labels: { kind: ["a"] },
			buckets: [1],
		});
		const base = await serve(
			undefined,
			emitting(() => work),
		);
		work.observe({ kind: "a" }, 0.5);
		const res = await fetch(`${base}/metrics`);
		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toBe("text/plain; version=0.0.4; charset=utf-8");
		expect([res.headers.get("cache-control"), res.headers.get("pragma")]).toEqual([
			"no-store",
			"no-cache",
		]);
		const text = await res.text();
		expect(text).toContain("# TYPE work_seconds histogram\n");
		expect(text).toContain('work_seconds_count{kind="a"} 1\n');
		expect(text).toContain("# TYPE auth_provider_process_cpu_user_seconds_total counter\n");
	});

	it("reads each gauge at every scrape, leaving out one whose read fails", async () => {
		let up = 1;
		const base = await serve(
			undefined,
			emitting(
				() =>
					gauge({ name: "up", help: "Up.", labels: { part: ["a"] } }, () => [
						{ labels: { part: "a" }, value: up },
					]),
				() =>
					gauge({ name: "broken", help: "Broken.", labels: {} }, () => {
						throw new Error("zq9");
					}),
			),
		);
		const scrape = async () => {
			const res = await fetch(`${base}/metrics`);
			expect(res.status).toBe(200);
			return res.text();
		};
		expect(await scrape()).toContain('# TYPE up gauge\nup{part="a"} 1\n');
		up = 0;
		const text = await scrape();
		expect(text).toContain('up{part="a"} 0\n');
		expect(text).toContain("# TYPE broken gauge\n# HELP");
		expect(text).not.toContain("zq9");
	});

	it("answers at the path set", async () => {
		const base = await serve({ path: "/internal/scrape" });
		expect((await fetch(`${base}/metrics`)).status).toBe(404);
		expect((await fetch(`${base}/internal/scrape`)).status).toBe(200);
	});

	it("keeps one set of process counts across assemblies", async () => {
		const typeLines = (text: string) =>
			text
				.split("\n")
				.filter((line) => line.startsWith("# TYPE auth_provider_nodejs_gc_duration_seconds "));
		for (const base of [await serve(), await serve()]) {
			expect(typeLines(await (await fetch(`${base}/metrics`)).text())).toHaveLength(1);
		}
	});
});

describe("refusals at boot", () => {
	it("refuses a path that is not one plain path, without printing it", async () => {
		for (const path of ["zq9", "/zq9/*", "/zq9?x=1", "/zq9#f", "/zq9 n", "/zq9\u0007"]) {
			const found = await refusals([http, metricsModule, prometheus], { path });
			expect(found).toHaveLength(1);
			expect(found[0]).toMatch(/^metrics-prometheus\.path: /);
			expect(found[0]).not.toContain("zq9");
		}
	});

	it("refuses to boot without metrics", async () => {
		expect(await refusals([http, prometheus])).toEqual([
			"metrics-prometheus: no module provides metrics",
		]);
	});

	it("refuses instruments the text cannot hold, naming each", async () => {
		const emitter = emitting(
			() => histogram({ name: "h", help: "", labels: { le: ["1"] }, buckets: [1] }),
			() => counter({ name: "auth_provider_process_start_time_seconds", help: "", labels: {} }),
			() => histogram({ name: "x", help: "", labels: {}, buckets: [1] }),
			() => counter({ name: "x_sum", help: "", labels: {} }),
			() => gauge({ name: "x_count", help: "", labels: {} }, () => []),
			() =>
				gauge(
					{ name: "auth_provider_process_cpu_user_seconds_total", help: "", labels: {} },
					() => [],
				),
			() => counter({ name: "auth_provider_nodejs_gc_duration_seconds_sum", help: "", labels: {} }),
		);
		expect(await refusals([http, metricsModule, prometheus, emitter])).toEqual([
			"metrics-prometheus:h: a histogram label is named le",
			"metrics-prometheus:auth_provider_process_start_time_seconds: a name it takes is the process's",
			"metrics-prometheus:x: a name it takes is another instrument's",
			"metrics-prometheus:x_sum: a name it takes is another instrument's",
			"metrics-prometheus:x_count: a name it takes is another instrument's",
			"metrics-prometheus:auth_provider_process_cpu_user_seconds_total: a name it takes is the process's",
			"metrics-prometheus:auth_provider_nodejs_gc_duration_seconds_sum: a name it takes is the process's",
		]);
	});
});

it("answers scrapes at /metrics when the operator names no path", () => {
	expect(section.parse({})).toEqual({ path: "/metrics" });
});
