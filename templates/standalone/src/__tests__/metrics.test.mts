/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createMetrics } from "../metrics.mjs";

function buildApp(probes: Parameters<ReturnType<typeof createMetrics>["route"]>[1]["probes"] = []) {
	const metrics = createMetrics();
	const app = express();
	app.use(metrics.middleware);
	app.use(metrics.route(express, { probes, probeTimeoutMs: 100 }));

	const api = express.Router();
	api.get("/widgets/:id", (_req, res) => {
		res.status(200).json({ ok: true });
	});
	api.get("/boom", (_req, res) => {
		res.status(500).json({ ok: false });
	});
	app.use("/api", api);
	return app;
}

describe("GET /metrics", () => {
	it("serves the Prometheus text exposition format", async () => {
		const res = await request(buildApp()).get("/metrics");

		expect(res.status).toBe(200);
		expect(res.headers["content-type"]).toContain("text/plain");
		// Node process defaults are namespaced so they cannot collide with
		// anything else scraped from the same job.
		expect(res.text).toContain("auth_provider_process_cpu_user_seconds_total");
	});

	it("records latency by method, route and status", async () => {
		const app = buildApp();
		await request(app).get("/api/widgets/42");
		await request(app).get("/api/boom");

		const res = await request(app).get("/metrics");

		expect(res.text).toContain('route="/api/widgets/:id"');
		expect(res.text).toContain('status="200"');
		expect(res.text).toContain('status="500"');
	});

	it("labels by the route pattern, not the URL, so the label set stays bounded", async () => {
		// Labelling by path would mint a series per id and eventually take down
		// the system that is supposed to be watching this one.
		const app = buildApp();
		for (const id of ["1", "2", "3"]) {
			await request(app).get(`/api/widgets/${id}`);
		}

		const res = await request(app).get("/metrics");
		const series = res.text
			.split("\n")
			.filter((l) => l.startsWith("http_request_duration_seconds_count"));

		expect(series.some((l) => l.includes('route="/api/widgets/:id"'))).toBe(true);
		expect(res.text).not.toContain('route="/api/widgets/1"');
	});

	it("collapses unmatched requests into a single bucket", async () => {
		// 404 probes from the internet carry attacker-chosen paths.
		const app = buildApp();
		await request(app).get(`/nope/${"x".repeat(50)}`);

		const res = await request(app).get("/metrics");

		expect(res.text).toContain('route="unmatched"');
		expect(res.text).not.toContain("xxxxx");
	});

	it("publishes a per-dependency gauge from the readiness probes", async () => {
		const app = buildApp([
			{ name: "redis", check: async () => "PONG" },
			{
				name: "session-store",
				check: async () => {
					throw new Error("ECONNREFUSED");
				},
			},
		]);

		const res = await request(app).get("/metrics");

		expect(res.text).toContain('auth_dependency_up{dependency="redis"} 1');
		expect(res.text).toContain('auth_dependency_up{dependency="session-store"} 0');
	});

	it("re-samples dependencies on every scrape instead of caching a verdict", async () => {
		let healthy = true;
		const app = buildApp([
			{
				name: "redis",
				check: async () => {
					if (!healthy) throw new Error("down");
					return "PONG";
				},
			},
		]);

		expect((await request(app).get("/metrics")).text).toContain(
			'auth_dependency_up{dependency="redis"} 1',
		);
		healthy = false;
		expect((await request(app).get("/metrics")).text).toContain(
			'auth_dependency_up{dependency="redis"} 0',
		);
	});

	it("joins an in-flight probe rather than issuing one per scrape", async () => {
		// A partitioned backend never answers, and a scrape loop would otherwise
		// stack one command per scrape against the dependency already in trouble.
		const check = vi.fn(() => new Promise(() => {}));
		const app = buildApp([{ name: "redis", check }]);

		await request(app).get("/metrics");
		await request(app).get("/metrics");

		expect(check).toHaveBeenCalledTimes(1);
	});

	it("is never cached", async () => {
		const res = await request(buildApp()).get("/metrics");

		expect(res.headers["cache-control"]).toBe("no-store");
	});
});
