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
import type { UserRepository } from "@o3co/auth-provider-core";
import { createAdapterFactory } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";

/**
 * Pins the operator-facing error for the nested `repositories.*` config.
 * Wiring code MUST flatten the adapter sub-section before calling
 * `factory.create(...)`; a caller that forwards a legacy flat config leaves
 * the adapter-specific fields missing, and the builder names exactly the
 * missing field.
 */
describe("nested repositories.* migration: builder-level error self-diagnosis", () => {
	it("http user builder emits a clear error when authenticateUrl is missing", async () => {
		// A legacy flat `repositories.user` section effectively reaches the
		// builder as `{ type }` alone: `.passthrough()` keeps `authenticateUrl`
		// at parse time, but the wiring flattens `{ type, <type>: { ... } }`,
		// so a flat field never reaches the builder.
		const userFactory = createAdapterFactory<UserRepository>("UserRepository");
		userFactory.register("http", (config) => {
			if (typeof config.authenticateUrl !== "string") {
				throw new Error('HttpUserRepository requires "authenticateUrl" in config');
			}
			throw new Error("unreachable — this test asserts the early throw above");
		});

		await expect(userFactory.create({ type: "http" })).rejects.toThrow(
			/HttpUserRepository requires "authenticateUrl" in config/,
		);
	});

	it("yaml user builder emits a clear error when path is missing", async () => {
		const userFactory = createAdapterFactory<UserRepository>("UserRepository");
		userFactory.register("yaml", (config) => {
			if (typeof config.path !== "string") {
				throw new Error('YAML user repository requires "path" in config');
			}
			throw new Error("unreachable");
		});

		await expect(userFactory.create({ type: "yaml" })).rejects.toThrow(
			/YAML user repository requires "path" in config/,
		);
	});

	it("flattened nested config (the post-migration wiring pattern) succeeds", async () => {
		const userFactory = createAdapterFactory<UserRepository>("UserRepository");
		userFactory.register("http", (config) => {
			if (typeof config.authenticateUrl !== "string") {
				throw new Error("should not reach here");
			}
			return {
				authenticate: async () => null,
				authenticateByToken: async () => null,
			} as UserRepository;
		});

		// Flatten as the wiring does: `{ type, http: { ... } }` → `{ type, ...http }`.
		const nestedRepositoriesUser = {
			type: "http",
			http: { authenticateUrl: "https://auth.example.com/verify" },
		};
		const adapterCfg =
			(nestedRepositoriesUser[nestedRepositoriesUser.type as "http"] as Record<string, unknown>) ??
			{};
		const flattened = { type: nestedRepositoriesUser.type, ...adapterCfg };

		const repo = await userFactory.create(flattened);
		expect(repo).toBeDefined();
	});
});
