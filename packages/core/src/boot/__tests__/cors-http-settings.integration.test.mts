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
 * The origins core's CORS middleware lets read are the `httpSettings` slot's,
 * and nothing else's: a composition without the slot allows no origin, and a
 * `cors` section in the configuration is read by nothing — kept as written
 * and named as ignored, unless a loaded module relocates it.
 * A slot whose origins break the slot's contract refuses the boot, naming the
 * member.
 */

import express, { Router } from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
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

/** A module providing `settings` eagerly. */
const httpModule = (settings: unknown) =>
	defineModule({
		name: "http",
		provides: { httpSettings: () => settings as HttpSettings },
		lifecycle: { httpSettings: { eager: true } },
	});

/** A booted app with `modules` beside the token route. */
const boot = async (modules: ReturnType<typeof defineModule>[]) => {
	const handle = await createApp({
		modules: [tokenRoute, ...modules],
		bootstrapComponents: {
			config: makeValidCoreConfig(),
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
	it("lets the origins the slot lists read, and no other", async () => {
		const { app, handle } = await boot([
			httpModule(createTestHttpSettings({ allowedOrigins: [SLOT_ORIGIN] })),
		]);
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

	it("mounts no CORS middleware when the slot lists no origin", async () => {
		const { app, handle } = await boot([
			httpModule(createTestHttpSettings({ allowedOrigins: [] })),
		]);
		try {
			const res = await request(app).post("/oauth/token").set("Origin", CONFIG_ORIGIN);
			expect(res.status).toBe(200);
			expect(res.headers["access-control-allow-origin"]).toBeUndefined();
			expect(res.headers.vary).toBeUndefined();
		} finally {
			await handle.dispose();
		}
	});

	it("builds a provider of the slot that nothing requires: one listing no origin mounts no CORS", async () => {
		const lazy = defineModule({
			name: "http",
			provides: { httpSettings: () => createTestHttpSettings({ allowedOrigins: [] }) },
		});
		const { app, handle } = await boot([lazy]);
		try {
			const res = await preflight(app, CONFIG_ORIGIN);
			expect(res.headers["access-control-allow-origin"]).toBeUndefined();
			expect(handle.components.httpSettings).toBeDefined();
		} finally {
			await handle.dispose();
		}
	});

	it("refuses a provider that answers undefined, naming httpSettings", async () => {
		await expect(boot([httpModule(undefined)])).rejects.toThrow(/httpSettings/);
	});

	it("lets the slot's origins alone read when the configuration writes cors beside it, naming the section as ignored", async () => {
		const warn = vi.fn();
		const handle = await createApp({
			modules: [tokenRoute, httpModule(createTestHttpSettings({ allowedOrigins: [SLOT_ORIGIN] }))],
			bootstrapComponents: {
				config: { ...makeValidCoreConfig(), cors: { allowedOrigins: [CONFIG_ORIGIN] } },
				pathResolver: (s: string) => s,
				logger: {
					trace: vi.fn(),
					debug: vi.fn(),
					info: vi.fn(),
					warn,
					error: vi.fn(),
					fatal: vi.fn(),
				},
			} as never,
		});
		try {
			const app = express();
			app.use(handle.router);
			expect((await preflight(app, SLOT_ORIGIN)).headers["access-control-allow-origin"]).toBe(
				SLOT_ORIGIN,
			);
			expect(
				(await preflight(app, CONFIG_ORIGIN)).headers["access-control-allow-origin"],
			).toBeUndefined();
			const ignored = warn.mock.calls.filter(
				([, message]) => message === "config_sections_ignored",
			);
			expect(ignored).toEqual([
				[{ sections: expect.arrayContaining(["cors"]) }, "config_sections_ignored"],
			]);
			expect(JSON.stringify(warn.mock.calls)).not.toContain(CONFIG_ORIGIN);
		} finally {
			await handle.dispose();
		}
	});

	it("reads a slot the host fills through overrideComponents", async () => {
		const handle = await createApp({
			modules: [tokenRoute],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
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

	it("allows no origin when nothing fills the slot", async () => {
		const { app, handle } = await boot([]);
		try {
			const res = await preflight(app, CONFIG_ORIGIN);
			expect(res.headers["access-control-allow-origin"]).toBeUndefined();
			expect(res.headers.vary).toBeUndefined();
		} finally {
			await handle.dispose();
		}
	});

	it("refuses a slot whose origin is not a serialized origin, naming the member and the index", async () => {
		await expect(
			boot([
				httpModule(createTestHttpSettings({ allowedOrigins: [SLOT_ORIGIN, `${SLOT_ORIGIN}/`] })),
			]),
		).rejects.toThrow(/httpSettings\.cors\.allowedOrigins\[1\]/);
	});

	it.each([
		["no cors member", { trustProxy: false }],
		["a list that is not a list", { trustProxy: false, cors: { allowedOrigins: SLOT_ORIGIN } }],
		["an entry that is not a string", { trustProxy: false, cors: { allowedOrigins: [42] } }],
	])("refuses a slot with %s, naming the member", async (_name, settings) => {
		await expect(boot([httpModule(Object.freeze(settings))])).rejects.toThrow(
			/httpSettings\.cors\.allowedOrigins/,
		);
	});
});
