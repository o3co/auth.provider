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

import type { Router } from "express";
import { describe, expect, it, vi } from "vitest";
import { createApp } from "#/app.mjs";
import type { AppConfig } from "#/config/application.schema.mjs";
import { GrantRegistry } from "#/grants/registry.mjs";
import { createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import type { LegacyModule as Module } from "#/modules/types.mjs";

const mockExpress = {
	Router: () =>
		({
			use: vi.fn().mockReturnThis(),
			get: vi.fn().mockReturnThis(),
			post: vi.fn().mockReturnThis(),
		}) as unknown as Router,
	json: () => vi.fn(),
	urlencoded: () => vi.fn(),
};

const mockConfig = {
	http: { port: 3000, trustProxy: false },
	oauth: {
		jwt: {
			signingKey: {
				provider: "local",
				local: { algorithm: "HS256", kid: "v0", secret: "test-secret", previousKeys: [] },
			},
		},
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
	},
} as unknown as AppConfig;

describe("createApp", () => {
	it("returns router, grantRegistry, and init function", () => {
		const result = createApp({
			express: mockExpress,
			config: mockConfig,
			keyStore: createSymmetricKeyStore("test-secret"),
			modules: [],
		});

		expect(result.router).toBeDefined();
		expect(result.grantRegistry).toBeInstanceOf(GrantRegistry);
		expect(typeof result.init).toBe("function");
	});

	it("init() calls module.init() with ModuleContext", async () => {
		const initFn = vi.fn();
		const testModule: Module = {
			name: "test",
			init: initFn,
		};

		const keyStore = createSymmetricKeyStore("test-secret");
		const result = createApp({
			express: mockExpress,
			config: mockConfig,
			keyStore,
			modules: [testModule],
		});

		await result.init();

		expect(initFn).toHaveBeenCalledTimes(1);
		const ctx = initFn.mock.calls[0][0];
		expect(ctx.config).toMatchObject(mockConfig);
		expect(ctx.keyStore).toBe(keyStore);
		expect(ctx.grantRegistry).toBeInstanceOf(GrantRegistry);
		expect(ctx.router).toBeDefined();
	});

	it("init() passes pathResolver from options to ModuleContext", async () => {
		const initFn = vi.fn();
		const testModule: Module = { name: "test", init: initFn };
		const pathResolver = (s: string) => `/resolved/${s}`;

		const result = createApp({
			express: mockExpress,
			pathResolver,
			config: mockConfig,
			keyStore: createSymmetricKeyStore("test-secret"),
			modules: [testModule],
		});

		await result.init();

		const ctx = initFn.mock.calls[0][0];
		expect(ctx.pathResolver).toBe(pathResolver);
	});

	it("init() calls modules in order", async () => {
		const order: string[] = [];
		const moduleA: Module = {
			name: "a",
			async init() {
				order.push("a");
			},
		};
		const moduleB: Module = {
			name: "b",
			async init() {
				order.push("b");
			},
		};

		const result = createApp({
			express: mockExpress,
			config: mockConfig,
			keyStore: createSymmetricKeyStore("test-secret"),
			modules: [moduleA, moduleB],
		});

		await result.init();

		expect(order).toEqual(["a", "b"]);
	});

	it("uses identity function as default pathResolver", async () => {
		const initFn = vi.fn();
		const testModule: Module = { name: "test", init: initFn };

		const result = createApp({
			express: mockExpress,
			config: mockConfig,
			keyStore: createSymmetricKeyStore("test-secret"),
			modules: [testModule],
		});

		await result.init();

		const ctx = initFn.mock.calls[0][0];
		expect(ctx.pathResolver("foo")).toBe("foo");
	});

	it("init() rejects when module configSchema requires missing config sections", async () => {
		const { z } = await import("zod");
		const moduleWithSchema: Module = {
			name: "needs-session",
			configSchema: z.object({ session: z.object({ secret: z.string() }) }),
			async init() {},
		};

		const result = createApp({
			express: mockExpress,
			config: mockConfig,
			keyStore: createSymmetricKeyStore("test-secret"),
			modules: [moduleWithSchema],
		});

		await expect(result.init()).rejects.toThrow();
	});

	it("wires healthcheck and jwks routes on router", () => {
		const routerMock = {
			use: vi.fn().mockReturnThis(),
			get: vi.fn().mockReturnThis(),
			post: vi.fn().mockReturnThis(),
		} as unknown as Router;

		const express = {
			...mockExpress,
			Router: () => routerMock,
		};

		createApp({
			express,
			config: mockConfig,
			keyStore: createSymmetricKeyStore("test-secret"),
			modules: [],
		});

		// Router.use should have been called for healthcheck and jwks sub-routers
		expect((routerMock.use as ReturnType<typeof vi.fn>).mock.calls.length).toBeGreaterThanOrEqual(
			1,
		);
	});
});
