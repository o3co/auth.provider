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
import { describe, expect, it, vi } from "vitest";
import type { Router } from "express";
import { createApp } from "../app.mjs";
import { GrantRegistry } from "../grants/registry.mjs";
import { createSymmetricKeyStore } from "../keys/KeyStore.mjs";
import type { Module } from "../modules/types.mjs";
import type { ClientRepository } from "../repositories/ClientRepository.mjs";
import type { CodeRepository } from "../repositories/CodeRepository.mjs";
import type { AppConfig } from "../config/application.schema.mjs";

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
	oauth: {
		jwt: { secret: "test-secret" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
	},
} as unknown as AppConfig;

describe("createApp", () => {
	it("returns router, grantRegistry, and init function", () => {
		const result = createApp(mockExpress, {
			config: mockConfig,
			keyStore: createSymmetricKeyStore("test-secret"),
			modules: [],
			clientRepository: {} as ClientRepository,
			codeRepository: {} as CodeRepository,
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
		const result = createApp(mockExpress, {
			config: mockConfig,
			keyStore,
			modules: [testModule],
			clientRepository: {} as ClientRepository,
			codeRepository: {} as CodeRepository,
		});

		await result.init();

		expect(initFn).toHaveBeenCalledTimes(1);
		const ctx = initFn.mock.calls[0][0];
		expect(ctx.config).toBe(mockConfig);
		expect(ctx.keyStore).toBe(keyStore);
		expect(ctx.grantRegistry).toBeInstanceOf(GrantRegistry);
		expect(ctx.router).toBeDefined();
	});

	it("init() passes pathResolver from options to ModuleContext", async () => {
		const initFn = vi.fn();
		const testModule: Module = { name: "test", init: initFn };
		const pathResolver = (s: string) => `/resolved/${s}`;

		const result = createApp(mockExpress, {
			pathResolver,
			config: mockConfig,
			keyStore: createSymmetricKeyStore("test-secret"),
			modules: [testModule],
			clientRepository: {} as ClientRepository,
			codeRepository: {} as CodeRepository,
		});

		await result.init();

		const ctx = initFn.mock.calls[0][0];
		expect(ctx.pathResolver).toBe(pathResolver);
	});

	it("init() calls modules in order", async () => {
		const order: string[] = [];
		const moduleA: Module = {
			name: "a",
			async init() { order.push("a"); },
		};
		const moduleB: Module = {
			name: "b",
			async init() { order.push("b"); },
		};

		const result = createApp(mockExpress, {
			config: mockConfig,
			keyStore: createSymmetricKeyStore("test-secret"),
			modules: [moduleA, moduleB],
			clientRepository: {} as ClientRepository,
			codeRepository: {} as CodeRepository,
		});

		await result.init();

		expect(order).toEqual(["a", "b"]);
	});

	it("uses identity function as default pathResolver", async () => {
		const initFn = vi.fn();
		const testModule: Module = { name: "test", init: initFn };

		const result = createApp(mockExpress, {
			config: mockConfig,
			keyStore: createSymmetricKeyStore("test-secret"),
			modules: [testModule],
			clientRepository: {} as ClientRepository,
			codeRepository: {} as CodeRepository,
		});

		await result.init();

		const ctx = initFn.mock.calls[0][0];
		expect(ctx.pathResolver("foo")).toBe("foo");
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

		createApp(express, {
			config: mockConfig,
			keyStore: createSymmetricKeyStore("test-secret"),
			modules: [],
			clientRepository: {} as ClientRepository,
			codeRepository: {} as CodeRepository,
		});

		// Router.use should have been called for healthcheck and jwks sub-routers
		expect((routerMock.use as ReturnType<typeof vi.fn>).mock.calls.length).toBeGreaterThanOrEqual(1);
	});
});
