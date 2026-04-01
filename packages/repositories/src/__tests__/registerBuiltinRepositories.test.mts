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

import type { CodeRepository, UserRepository } from "@o3co/auth-provider-core";
import { RepositoryFactory } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { registerBuiltinRepositories } from "../index.mjs";

describe("registerBuiltinRepositories", () => {
	it("registers 'http' type in userFactory", async () => {
		const userFactory = new RepositoryFactory<UserRepository>("user");
		const codeFactory = new RepositoryFactory<CodeRepository>("code");

		registerBuiltinRepositories({ userFactory, codeFactory });

		await expect(userFactory.create({ type: "unknown" })).rejects.toThrow(/http/);
	});

	it("registers 'redis' type in codeFactory", async () => {
		const userFactory = new RepositoryFactory<UserRepository>("user");
		const codeFactory = new RepositoryFactory<CodeRepository>("code");

		registerBuiltinRepositories({ userFactory, codeFactory });

		await expect(codeFactory.create({ type: "unknown" })).rejects.toThrow(/redis/);
	});
});
