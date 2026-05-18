/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * boot/__tests__/grant-middleware.integration.test.mts
 *
 * Integration tests for the `grantMiddleware` contribution kind.
 *
 * Verifies:
 *   1. Cross-loop ordering — a factory returning a non-null RequestHandler is
 *      invoked and its handler runs BEFORE a `routes` contribution mounted at
 *      `/oauth` (the bundled oauthModule's mountPath). This pins the
 *      structural ordering claim that makes the kind useful for DPoP / mTLS:
 *      the middleware MUST inspect the request before the OAuth /token
 *      handler runs.
 *   2. Null-skip — a factory returning null is invoked (so it can decide
 *      disabled-by-config) but no handler is mounted; the routes contribution
 *      sees the request without any pre-route middleware running.
 *   3. Module-registration order — when two modules contribute
 *      `grantMiddleware`, the first-registered fires first.
 *
 * Per Wave 2 Token-binding Cluster spec §4.7 / Phase 2 DPoP spec §11.1.
 */

import express, { type RequestHandler, Router } from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createApp } from "../../index.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import type { BootstrapMap } from "../types.mjs";

// ---------------------------------------------------------------------------
// Shared bootstrap stub
// ---------------------------------------------------------------------------

const minBoot = {
	config: makeValidCoreConfig() as never,
	pathResolver: (s: string) => s,
} satisfies Record<string, unknown> as BootstrapMap;

// ---------------------------------------------------------------------------
// Fixture: build a routes contribution that mounts a `/token` handler under
// `/oauth` — mirrors the bundled oauthModule's mountPath shape so the test
// exercises the actual cross-loop ordering claim against the real grant-
// dispatch path (`/oauth/token`).
// ---------------------------------------------------------------------------

function tokenRouteContribution(record: (label: string) => void) {
	const tokenRouter = Router();
	tokenRouter.post("/token", (_req, res) => {
		record("route");
		res.status(200).json({ ok: true });
	});
	return {
		id: "test-oauth-endpoints",
		mountPath: "/oauth",
		handler: tokenRouter as never,
	};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ContributesMap.grantMiddleware composition", () => {
	it("mounts the returned handler on /oauth/token and runs it BEFORE the OAuth grant dispatch handler", async () => {
		const events: string[] = [];
		const observerMw: RequestHandler = (_req, _res, next) => {
			events.push("mw");
			next();
		};

		const observerModule = defineModule({
			name: "observer",
			requires: [],
			optional: [],
			contributes: {
				grantMiddleware: [() => observerMw],
				routes: [() => tokenRouteContribution((label) => events.push(label))],
			},
		});

		const handle = await createApp({
			modules: [observerModule],
			bootstrapComponents: minBoot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app).post("/oauth/token").send({});
		expect(res.status).toBe(200);

		// Cross-loop ordering: the grantMiddleware MUST run before the route
		// handler. This is the load-bearing property — DPoP / mTLS depend on
		// it to inspect/replace the request before grant dispatch.
		expect(events).toEqual(["mw", "route"]);

		await handle.dispose();
	});

	it("skips factories that return null (disabled-by-config path) — route handler sees no pre-route middleware", async () => {
		const factory = vi.fn(() => null);
		const events: string[] = [];

		const nullModule = defineModule({
			name: "null-mw",
			requires: [],
			optional: [],
			contributes: {
				grantMiddleware: [factory],
				routes: [() => tokenRouteContribution((label) => events.push(label))],
			},
		});

		const handle = await createApp({
			modules: [nullModule],
			bootstrapComponents: minBoot,
		});

		// Factory must have been invoked so it could decide null = skip.
		expect(factory).toHaveBeenCalledTimes(1);

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app).post("/oauth/token").send({});
		expect(res.status).toBe(200);

		// Only the route handler fired; the null-returning factory contributed
		// no mounted middleware.
		expect(events).toEqual(["route"]);

		await handle.dispose();
	});

	it("runs grantMiddleware contributions in module-registration order", async () => {
		const events: string[] = [];

		const moduleA = defineModule({
			name: "mw-a",
			requires: [],
			optional: [],
			contributes: {
				grantMiddleware: [
					() => (_req, _res, next) => {
						events.push("a");
						next();
					},
				],
			},
		});
		const moduleB = defineModule({
			name: "mw-b",
			requires: [],
			optional: [],
			contributes: {
				grantMiddleware: [
					() => (_req, _res, next) => {
						events.push("b");
						next();
					},
				],
				routes: [() => tokenRouteContribution((label) => events.push(label))],
			},
		});

		const handle = await createApp({
			modules: [moduleA, moduleB],
			bootstrapComponents: minBoot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app).post("/oauth/token").send({});
		expect(res.status).toBe(200);

		// Module-registration order: moduleA's mw fires before moduleB's mw,
		// both fire before the route handler.
		expect(events).toEqual(["a", "b", "route"]);

		await handle.dispose();
	});
});
