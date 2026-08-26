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
import { createRouter } from "#/routes/Readiness.mjs";

function buildApp(opts: Omit<Parameters<typeof createRouter>[1], "timeoutMs">) {
	const app = express();
	app.use(createRouter(express, { timeoutMs: 100, ...opts }));
	return app;
}

describe("GET /readyz", () => {
	it("answers 200 when every probe succeeds", async () => {
		const app = buildApp({ probes: [{ name: "redis", check: async () => "PONG" }] });

		const res = await request(app).get("/readyz");

		expect(res.status).toBe(200);
		expect(res.body.status).toBe("ready");
		expect(res.body.checks).toEqual([expect.objectContaining({ name: "redis", ok: true })]);
	});

	it("answers 503 and names the failing dependency", async () => {
		const app = buildApp({
			probes: [
				{ name: "redis", check: async () => "PONG" },
				{
					name: "session-store",
					check: async () => {
						throw new Error("ECONNREFUSED 127.0.0.1:6379");
					},
				},
			],
		});

		const res = await request(app).get("/readyz");

		expect(res.status).toBe(503);
		expect(res.body.status).toBe("unready");
		const failed = res.body.checks.find((c: { name: string }) => c.name === "session-store");
		expect(failed.ok).toBe(false);
	});

	it("keeps the driver's error message out of the response body by default", async () => {
		// The endpoint is unauthenticated by design, and a driver error names
		// the internal host and port it failed to reach.
		const logger = { warn: vi.fn(), error: vi.fn() };
		const app = buildApp({
			logger,
			probes: [
				{
					name: "redis",
					check: async () => {
						throw new Error("connect ECONNREFUSED 10.0.3.14:6379");
					},
				},
			],
		});

		const res = await request(app).get("/readyz");

		expect(res.status).toBe(503);
		expect(res.body.checks[0]).toEqual({
			name: "redis",
			ok: false,
			durationMs: expect.any(Number),
		});
		expect(JSON.stringify(res.body)).not.toContain("10.0.3.14");

		// The detail is not discarded — it goes where the reader is authenticated.
		expect(logger.warn).toHaveBeenCalledTimes(1);
		const [payload, msg] = logger.warn.mock.calls[0] as [Record<string, unknown>, string];
		expect(msg).toBe("readiness_probe_failed");
		expect(JSON.stringify(payload)).toContain("10.0.3.14");
	});

	it("includes the error message when the operator opts in", async () => {
		const app = buildApp({
			includeErrorDetail: true,
			probes: [
				{
					name: "redis",
					check: async () => {
						throw new Error("connect ECONNREFUSED 10.0.3.14:6379");
					},
				},
			],
		});

		const res = await request(app).get("/readyz");

		expect(res.body.checks[0].error).toContain("10.0.3.14");
	});

	it("answers 200 when nothing registered a probe", async () => {
		// A memory-only deployment has no backing dependency to be unready for.
		const res = await request(buildApp({ probes: [] })).get("/readyz");

		expect(res.status).toBe(200);
		expect(res.body.status).toBe("ready");
	});

	it("is never cached — a stale ready answer outlives the outage it describes", async () => {
		const res = await request(buildApp({ probes: [] })).get("/readyz");

		expect(res.headers["cache-control"]).toBe("no-store");
	});

	it("re-runs every probe per request rather than caching the first verdict", async () => {
		// Readiness is a question about *now*. A route that answered from a
		// boot-time verdict would keep reporting ready through the outage it
		// exists to detect.
		let healthy = true;
		const check = vi.fn(async () => {
			if (!healthy) throw new Error("down");
			return "PONG";
		});
		const app = buildApp({ probes: [{ name: "redis", check }] });

		expect((await request(app).get("/readyz")).status).toBe(200);
		healthy = false;
		expect((await request(app).get("/readyz")).status).toBe(503);
		healthy = true;
		expect((await request(app).get("/readyz")).status).toBe(200);
		expect(check).toHaveBeenCalledTimes(3);
	});
});
