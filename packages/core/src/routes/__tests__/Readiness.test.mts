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
import { describe, expect, it } from "vitest";
import { createRouter } from "#/routes/Readiness.mjs";

function buildApp(opts: Parameters<typeof createRouter>[1]) {
	const app = express();
	app.use(createRouter(express, opts));
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
		expect(failed.error).toContain("ECONNREFUSED");
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

	it("reads probes at request time so a late registration is still seen", async () => {
		// Probes are registered by builders during boot, and the route may be
		// constructed from a live registrar rather than a settled array.
		const probes: Array<{ name: string; check: () => Promise<unknown> }> = [];
		const app = buildApp({ probes });

		const before = await request(app).get("/readyz");
		expect(before.body.checks).toEqual([]);

		probes.push({
			name: "late",
			check: async () => {
				throw new Error("down");
			},
		});

		const after = await request(app).get("/readyz");
		expect(after.status).toBe(503);
		expect(after.body.checks).toHaveLength(1);
	});
});
