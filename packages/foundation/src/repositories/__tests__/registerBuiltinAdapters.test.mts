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

import {
	AdapterFactoryError,
	createAdapterFactory,
	type UserRepository,
} from "@o3co/auth-provider-core";
import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { registerBuiltinAdapters } from "#/index.mjs";

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

describe("registerBuiltinAdapters", () => {
	it("registers 'http' type in userFactory", async () => {
		const userFactory = createAdapterFactory<UserRepository>("UserRepository");

		registerBuiltinAdapters({ userFactory });

		try {
			await userFactory.create({ type: "unknown" });
			throw new Error("should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(AdapterFactoryError);
			const e = err as AdapterFactoryError;
			expect(e.reason).toBe("unknown");
			expect(e.kind).toBe("UserRepository");
			expect(e.registered).toContain("http");
		}
	});

	it("http builder creates a working HttpUserRepository", async () => {
		const userFactory = createAdapterFactory<UserRepository>("UserRepository");
		registerBuiltinAdapters({ userFactory });

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

	it("http builder coerces string timeout to number (env-override path)", async () => {
		const userFactory = createAdapterFactory<UserRepository>("UserRepository");
		registerBuiltinAdapters({ userFactory });

		const repo = await userFactory.create({
			type: "http",
			authenticateUrl: `${BASE_URL}/auth`,
			authenticateByTokenUrl: `${BASE_URL}/auth/token`,
			timeout: "1234", // string, as HOCON env override produces
		});
		expect(repo).toBeDefined();
		// HttpUserRepository doesn't expose timeout publicly; we verify it didn't throw
		// and works via the MSW fixture. The coercion path is internal.
		const user = await repo.authenticate("alice", "pass");
		expect(user).not.toBeNull();
	});

	it("http builder throws when authenticateUrl is missing", async () => {
		const userFactory = createAdapterFactory<UserRepository>("UserRepository");
		registerBuiltinAdapters({ userFactory });

		await expect(userFactory.create({ type: "http", timeout: 5000 })).rejects.toThrow(
			/authenticateUrl/,
		);
	});

	it("http builder throws when authenticateByTokenUrl is missing", async () => {
		const userFactory = createAdapterFactory<UserRepository>("UserRepository");
		registerBuiltinAdapters({ userFactory });

		await expect(
			userFactory.create({
				type: "http",
				authenticateUrl: `${BASE_URL}/auth`,
				timeout: 5000,
			}),
		).rejects.toThrow(/authenticateByTokenUrl/);
	});

	// #285: the builder is where a deployment's configuration first meets the
	// adapter, so every rejection below is a boot failure rather than a
	// first-login failure.
	describe("#285: configuration is rejected at build time", () => {
		const build = (over: Record<string, unknown>) => {
			const userFactory = createAdapterFactory<UserRepository>("UserRepository");
			registerBuiltinAdapters({ userFactory });
			return userFactory.create({
				type: "http",
				authenticateUrl: `${BASE_URL}/auth`,
				authenticateByTokenUrl: `${BASE_URL}/auth/token`,
				timeout: 5000,
				...over,
			});
		};

		it("refuses a plaintext Store URL on a routable host", async () => {
			await expect(build({ authenticateUrl: "http://users.example.com/auth" })).rejects.toThrow(
				/authenticateUrl/,
			);
		});

		it('refuses a blank timeout — HOCON substitutes an empty env var as ""', async () => {
			// `Number("")` is 0, and `setTimeout(fn, 0)` aborts every request
			// immediately. Previously this silently fell back to 5000, which hid
			// the misconfiguration instead of surfacing it.
			await expect(build({ timeout: "" })).rejects.toThrow(/timeout/);
		});

		it("refuses a non-numeric timeout instead of silently defaulting", async () => {
			await expect(build({ timeout: "soon" })).rejects.toThrow(/timeout/);
		});

		it("refuses a non-positive or fractional timeout", async () => {
			await expect(build({ timeout: 0 })).rejects.toThrow(/timeout/);
			await expect(build({ timeout: -1 })).rejects.toThrow(/timeout/);
			await expect(build({ timeout: 1.5 })).rejects.toThrow(/timeout/);
		});

		it("defaults timeout to 5000 when the key is absent entirely", async () => {
			const userFactory = createAdapterFactory<UserRepository>("UserRepository");
			registerBuiltinAdapters({ userFactory });
			const repo = await userFactory.create({
				type: "http",
				authenticateUrl: `${BASE_URL}/auth`,
				authenticateByTokenUrl: `${BASE_URL}/auth/token`,
			});
			await expect(repo.authenticate("alice", "pass")).resolves.not.toBeNull();
		});

		it("coerces a string maxResponseBytes and applies it (env-override path)", async () => {
			const repo = await build({ maxResponseBytes: "64" });
			server.use(
				http.post(`${BASE_URL}/auth`, () =>
					HttpResponse.json({ id: "u1", username: "alice", pad: "x".repeat(4096) }),
				),
			);
			await expect(repo.authenticate("alice", "pass")).rejects.toThrow(/64-byte cap/);
		});

		it("refuses a non-numeric maxResponseBytes", async () => {
			await expect(build({ maxResponseBytes: "lots" })).rejects.toThrow(/maxResponseBytes/);
		});

		it("refuses a value that is neither a number nor a string", async () => {
			// HOCON types a bare `timeout = true` as a boolean, and a mis-nested
			// section arrives as an object. Neither is coerced into a plausible
			// number — both are rejected by name.
			await expect(build({ timeout: true })).rejects.toThrow(/timeout/);
			await expect(build({ maxResponseBytes: { bytes: 2048 } })).rejects.toThrow(
				/maxResponseBytes/,
			);
		});
	});
});
