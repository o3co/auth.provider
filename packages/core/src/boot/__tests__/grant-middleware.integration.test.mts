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

/**
 * boot/__tests__/grant-middleware.integration.test.mts
 *
 * Integration tests for the `grantMiddleware` contribution kind.
 *
 * Verifies:
 *   1. A factory returning a non-null RequestHandler is invoked and its
 *      handler is mounted on `/token` BEFORE grant dispatch.
 *   2. A factory returning null is invoked but its result is skipped —
 *      no handler is mounted.
 *
 * Per Wave 2 Token-binding Cluster spec §4.7 / Phase 2 DPoP spec §11.1.
 */

import express, { type RequestHandler } from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createApp } from "../../index.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import type { BootstrapMap } from "../types.mjs";

// ---------------------------------------------------------------------------
// Shared bootstrap stub (same pattern as integration.test.mts)
// ---------------------------------------------------------------------------

const minBoot = {
	config: makeValidCoreConfig() as never,
	pathResolver: (s: string) => s,
} satisfies Record<string, unknown> as BootstrapMap;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ContributesMap.grantMiddleware composition", () => {
	it("invokes grantMiddleware factories and mounts the returned handler on /token", async () => {
		const observed = vi.fn();
		const observerMw: RequestHandler = (req, _res, next) => {
			observed(req.method, req.path);
			next();
		};

		const observerModule = defineModule({
			name: "observer",
			requires: [],
			optional: [],
			contributes: {
				grantMiddleware: [() => observerMw],
			},
		});

		const handle = await createApp({
			modules: [observerModule],
			bootstrapComponents: minBoot,
		});

		// Wrap the router in a real Express app for supertest.
		const app = express();
		app.use(handle.router);
		// Add a catch-all so supertest gets a 200 instead of 404 on /token.
		app.use("/token", (_req, res) => {
			res.status(200).json({ ok: true });
		});

		await request(app).post("/token").send({});

		expect(observed).toHaveBeenCalledWith("POST", "/");

		await handle.dispose();
	});

	it("skips factories that return null (disabled-by-config path)", async () => {
		const factory = vi.fn(() => null);

		const nullModule = defineModule({
			name: "null-mw",
			requires: [],
			optional: [],
			contributes: {
				grantMiddleware: [factory],
			},
		});

		const handle = await createApp({
			modules: [nullModule],
			bootstrapComponents: minBoot,
		});

		// Factory must have been invoked (to decide null = skip).
		expect(factory).toHaveBeenCalledTimes(1);

		// Wrap router; no grantMiddleware handler should intercept /token.
		const intercepted = vi.fn();
		const app = express();
		app.use(handle.router);
		app.use("/token", (_req, res) => {
			intercepted();
			res.status(200).json({ ok: true });
		});

		const res = await request(app).post("/token").send({});
		expect(res.status).toBe(200);
		// The null-returning factory produced no mounted middleware —
		// the catch-all runs and intercepted is called.
		expect(intercepted).toHaveBeenCalledTimes(1);

		await handle.dispose();
	});
});
