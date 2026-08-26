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
import { createRouter } from "#/routes/Healthcheck.mjs";

function buildApp(opts?: Parameters<typeof createRouter>[1]) {
	const app = express();
	app.use(createRouter(express, opts));
	return app;
}

describe("GET /_healthcheck", () => {
	it("answers 200 with the liveness body", async () => {
		const res = await request(buildApp()).get("/_healthcheck");

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ status: "ok" });
	});

	it("touches no dependency, so it cannot be made to fail by one", async () => {
		// This is the whole contract: liveness answers for the process, not for
		// what the process talks to. Wiring it to a backend probe would turn one
		// Redis outage into a cluster-wide restart loop.
		const app = buildApp();

		const results = await Promise.all(
			[1, 2, 3].map(() =>
				request(app)
					.get("/_healthcheck")
					.then((r) => r.status),
			),
		);

		expect(results).toEqual([200, 200, 200]);
	});

	it("honours a custom path", async () => {
		const app = buildApp({ path: "/healthz" });

		expect((await request(app).get("/healthz")).status).toBe(200);
		expect((await request(app).get("/_healthcheck")).status).toBe(404);
	});
});
