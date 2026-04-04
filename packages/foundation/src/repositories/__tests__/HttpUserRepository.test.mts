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

import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { HttpUserRepository } from "../HttpUserRepository.mjs";

const BASE_URL = "http://localhost:18080";

const mockUser = { id: "user-1", username: "alice" };

const handlers = [
	http.post(`${BASE_URL}/user/authenticate`, async ({ request }) => {
		const body = (await request.json()) as { email?: string; password?: string };
		if (body.email === "alice@example.com" && body.password === "correct-pass") {
			return HttpResponse.json(mockUser, { status: 200 });
		}
		return new HttpResponse(null, { status: 401 });
	}),
	http.post(`${BASE_URL}/user/authenticate/token`, async ({ request }) => {
		const body = (await request.json()) as { token?: string };
		if (body.token === "valid-token") {
			return HttpResponse.json(mockUser, { status: 200 });
		}
		return new HttpResponse(null, { status: 401 });
	}),
];

const server = setupServer(...handlers);

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("HttpUserRepository", () => {
	const repo = new HttpUserRepository({
		authenticateUrl: `${BASE_URL}/user/authenticate`,
		authenticateByTokenUrl: `${BASE_URL}/user/authenticate/token`,
		timeout: 5000,
	});

	describe("authenticate", () => {
		it("returns user on success", async () => {
			const user = await repo.authenticate("alice@example.com", "correct-pass");
			expect(user).not.toBeNull();
			expect(user?.id).toBe("user-1");
			expect(user?.username).toBe("alice");
		});

		it("sends email field (not username) in request body", async () => {
			let capturedBody: Record<string, unknown> | null = null;
			server.use(
				http.post(`${BASE_URL}/user/authenticate`, async ({ request }) => {
					capturedBody = (await request.json()) as Record<string, unknown>;
					return HttpResponse.json(mockUser, { status: 200 });
				}),
			);
			await repo.authenticate("alice@example.com", "correct-pass");
			expect(capturedBody).not.toBeNull();
			expect(capturedBody).toHaveProperty("email", "alice@example.com");
			expect(capturedBody).not.toHaveProperty("username");
		});

		it("returns null on 401", async () => {
			const user = await repo.authenticate("alice@example.com", "wrong-pass");
			expect(user).toBeNull();
		});

		it("throws on unexpected HTTP status", async () => {
			server.use(
				http.post(`${BASE_URL}/user/authenticate`, () => {
					return new HttpResponse(null, { status: 500 });
				}),
			);
			await expect(repo.authenticate("alice@example.com", "pass")).rejects.toThrow(
				"Unexpected HTTP status 500",
			);
		});
	});

	describe("authenticateByToken", () => {
		it("returns user on success", async () => {
			const user = await repo.authenticateByToken("valid-token");
			expect(user).not.toBeNull();
			expect(user?.id).toBe("user-1");
			expect(user?.username).toBe("alice");
		});

		it("returns null on 401", async () => {
			const user = await repo.authenticateByToken("invalid-token");
			expect(user).toBeNull();
		});
	});
});
