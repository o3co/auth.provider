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
 * The origins core's CORS middleware lets read are the `httpSettings` slot's
 * when the composition holds it, and the configuration's `cors.allowedOrigins`
 * only when it holds none: never the two mixed. A slot whose origins break the
 * slot's contract refuses the boot, naming the member, as the configuration's
 * schema refuses the same origins at its key.
 */

import express, { Router } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import type { HttpSettings } from "../../deployment/types.mjs";
import { createApp } from "../../index.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createTestHttpSettings } from "../../testing/slots/httpSettings.mjs";

const SLOT_ORIGIN = "https://slot.example";
const CONFIG_ORIGIN = "https://config.example";

/** The token route, standing in for the oauth module's: a CORS-enabled path. */
const tokenRoute = defineModule({
	name: "token-endpoint",
	contributes: {
		routes: [
			() => {
				const router = Router();
				router.post("/token", (_req, res) => {
					res.status(200).json({ ok: true });
				});
				return { id: "token-endpoint", mountPath: "/oauth", handler: router };
			},
		],
	},
});

/** A module providing `settings` as the `http` module does: eagerly, since core reads it. */
const httpModule = (settings: unknown) =>
	defineModule({
		name: "http",
		provides: { httpSettings: () => settings as HttpSettings },
		lifecycle: { httpSettings: { eager: true } },
	});

/** A booted app with `cors.allowedOrigins` configured as `configured`, and `modules` beside the token route. */
const boot = async (configured: readonly string[], modules: ReturnType<typeof defineModule>[]) => {
	const handle = await createApp({
		modules: [tokenRoute, ...modules],
		bootstrapComponents: {
			config: { ...makeValidCoreConfig(), cors: { allowedOrigins: [...configured] } },
			pathResolver: (s: string) => s,
		} as never,
	});
	const app = express();
	app.use(handle.router);
	return { app, handle };
};

/** A preflight for the token endpoint from `origin`. */
const preflight = (app: express.Express, origin: string) =>
	request(app)
		.options("/oauth/token")
		.set("Origin", origin)
		.set("Access-Control-Request-Method", "POST");

describe("the CORS mount reads the httpSettings slot when the composition holds it", () => {
	it("lets the origins the slot lists read, and not the configuration's", async () => {
		const { app, handle } = await boot(
			[CONFIG_ORIGIN],
			[httpModule(createTestHttpSettings({ allowedOrigins: [SLOT_ORIGIN] }))],
		);
		try {
			const fromSlot = await preflight(app, SLOT_ORIGIN);
			expect(fromSlot.status).toBe(204);
			expect(fromSlot.headers["access-control-allow-origin"]).toBe(SLOT_ORIGIN);

			const fromConfig = await preflight(app, CONFIG_ORIGIN);
			expect(fromConfig.headers["access-control-allow-origin"]).toBeUndefined();
		} finally {
			await handle.dispose();
		}
	});

	it("mounts no CORS middleware when the slot lists no origin, whatever the configuration lists", async () => {
		const { app, handle } = await boot(
			[CONFIG_ORIGIN],
			[httpModule(createTestHttpSettings({ allowedOrigins: [] }))],
		);
		try {
			const res = await request(app).post("/oauth/token").set("Origin", CONFIG_ORIGIN);
			expect(res.status).toBe(200);
			expect(res.headers["access-control-allow-origin"]).toBeUndefined();
			expect(res.headers.vary).toBeUndefined();
		} finally {
			await handle.dispose();
		}
	});

	it("builds a provider of the slot that nothing requires: one listing no origin wins over cors.allowedOrigins", async () => {
		const lazy = defineModule({
			name: "http",
			provides: { httpSettings: () => createTestHttpSettings({ allowedOrigins: [] }) },
		});
		const { app, handle } = await boot([CONFIG_ORIGIN], [lazy]);
		try {
			const res = await preflight(app, CONFIG_ORIGIN);
			expect(res.headers["access-control-allow-origin"]).toBeUndefined();
			expect(handle.components.httpSettings).toBeDefined();
		} finally {
			await handle.dispose();
		}
	});

	it("reads a slot the host fills through overrideComponents", async () => {
		const handle = await createApp({
			modules: [tokenRoute],
			bootstrapComponents: {
				config: { ...makeValidCoreConfig(), cors: { allowedOrigins: [CONFIG_ORIGIN] } },
				pathResolver: (s: string) => s,
			} as never,
			overrideComponents: {
				httpSettings: createTestHttpSettings({ allowedOrigins: [SLOT_ORIGIN] }),
			},
		});
		try {
			const app = express();
			app.use(handle.router);
			const res = await preflight(app, SLOT_ORIGIN);
			expect(res.headers["access-control-allow-origin"]).toBe(SLOT_ORIGIN);
		} finally {
			await handle.dispose();
		}
	});

	it("reads the configuration's list when nothing fills the slot", async () => {
		const { app, handle } = await boot([CONFIG_ORIGIN], []);
		try {
			const res = await preflight(app, CONFIG_ORIGIN);
			expect(res.headers["access-control-allow-origin"]).toBe(CONFIG_ORIGIN);
		} finally {
			await handle.dispose();
		}
	});

	it("refuses a slot whose origin is not a serialized origin, naming the member and the index", async () => {
		await expect(
			boot(
				[],
				[httpModule(createTestHttpSettings({ allowedOrigins: [SLOT_ORIGIN, `${SLOT_ORIGIN}/`] }))],
			),
		).rejects.toThrow(/httpSettings\.cors\.allowedOrigins\[1\]/);
	});

	it.each([
		["no cors member", { trustProxy: false }],
		["a list that is not a list", { trustProxy: false, cors: { allowedOrigins: SLOT_ORIGIN } }],
		["an entry that is not a string", { trustProxy: false, cors: { allowedOrigins: [42] } }],
	])("refuses a slot with %s, naming the member", async (_name, settings) => {
		await expect(boot([], [httpModule(Object.freeze(settings))])).rejects.toThrow(
			/httpSettings\.cors\.allowedOrigins/,
		);
	});
});
