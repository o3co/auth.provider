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
import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { registerBuiltinRepositories } from "../index.mjs";

const BASE_URL = "http://localhost:19090";
const mockUser = { id: "u1", username: "alice" };

const server = setupServer(
	http.post(`${BASE_URL}/auth`, async ({ request }) => {
		const body = (await request.json()) as { email?: string; password?: string };
		if (body.email === "alice" && body.password === "pass") {
			return HttpResponse.json(mockUser, { status: 200 });
		}
		return new HttpResponse(null, { status: 401 });
	}),
	http.post(`${BASE_URL}/auth/token`, async ({ request }) => {
		const body = (await request.json()) as { token?: string };
		if (body.token === "valid") {
			return HttpResponse.json(mockUser, { status: 200 });
		}
		return new HttpResponse(null, { status: 401 });
	}),
);

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

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

	it("http builder creates a working HttpUserRepository", async () => {
		const userFactory = new RepositoryFactory<UserRepository>("user");
		const codeFactory = new RepositoryFactory<CodeRepository>("code");
		registerBuiltinRepositories({ userFactory, codeFactory });

		const repo = await userFactory.create({
			type: "http",
			authenticateUrl: `${BASE_URL}/auth`,
			authenticateByTokenUrl: `${BASE_URL}/auth/token`,
			timeout: 5000,
		});

		const user = await repo.authenticate("alice", "pass");
		expect(user).not.toBeNull();
		expect(user?.username).toBe("alice");

		const byToken = await repo.authenticateByToken("valid");
		expect(byToken).not.toBeNull();

		const invalid = await repo.authenticate("alice", "wrong");
		expect(invalid).toBeNull();
	});

	it("http builder throws when authenticateUrl is missing", async () => {
		const userFactory = new RepositoryFactory<UserRepository>("user");
		const codeFactory = new RepositoryFactory<CodeRepository>("code");
		registerBuiltinRepositories({ userFactory, codeFactory });

		await expect(userFactory.create({ type: "http", timeout: 5000 })).rejects.toThrow(
			/authenticateUrl/,
		);
	});

	it("redis builder throws when endpointUri is missing", async () => {
		const userFactory = new RepositoryFactory<UserRepository>("user");
		const codeFactory = new RepositoryFactory<CodeRepository>("code");
		registerBuiltinRepositories({ userFactory, codeFactory });

		await expect(codeFactory.create({ type: "redis" })).rejects.toThrow(/endpointUri/);
	});
});
