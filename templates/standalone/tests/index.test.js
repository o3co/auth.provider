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

import axios from "axios";
import jwt from "jsonwebtoken";
import { describe, expect, it } from "vitest";

const BASE_URL = process.env.API_BASE_URL || "http://localhost:3000";
const JWT_SECRET = process.env.OAUTH_JWT_SECRET || "your-token-secret";

const client = axios.create({
	baseURL: BASE_URL,
	withCredentials: true,
	validateStatus: () => true,
});

const _extractCookies = (res) => (res.headers["set-cookie"] ?? []).join("; ");

/**
 * The server's own origin, as a browser would report it.
 *
 * Since #272 `POST /session/login` and `POST /session/logout` reject a request
 * that carries neither a same-origin `Origin`/`Referer` nor a valid
 * double-submit CSRF token. A browser sets `Origin` on its own; a scripted
 * client like this one has to say it.
 */
const SERVER_ORIGIN = new URL(BASE_URL).origin;

/** POST to a state-changing session route the way a same-origin browser would. */
const sessionPost = (path, data, config = {}) =>
	client.post(path, data, {
		...config,
		headers: { Origin: SERVER_ORIGIN, ...(config.headers ?? {}) },
	});

describe("POST /oauth/introspect", () => {
	// Helper: self-introspect sends the token as both Bearer credential and body parameter
	const selfIntrospect = (token, contentType = "application/json") => {
		const headers = {
			Authorization: `Bearer ${token}`,
			"Content-Type": contentType,
		};
		const data =
			contentType === "application/x-www-form-urlencoded"
				? `token=${encodeURIComponent(token)}`
				: { token };
		return client.post("/oauth/introspect", data, { headers });
	};

	it("returns 401 when no authentication is provided", async () => {
		const res = await client.post("/oauth/introspect", {});
		expect(res.status).toBe(401);
	});

	describe("self-introspect (JSON)", () => {
		it("returns active: true for a valid JWT", async () => {
			const token = jwt.sign({ user: { id: 1 }, scopes: ["read"] }, JWT_SECRET, {
				expiresIn: 60,
			});
			const res = await selfIntrospect(token);
			expect(res.status).toBe(200);
			expect(res.data.active).toBe(true);
		});

		it("returns scope as space-separated string per RFC 7662", async () => {
			const token = jwt.sign({ user: { id: 1 }, scopes: ["read", "write"] }, JWT_SECRET, {
				expiresIn: 60,
			});
			const res = await selfIntrospect(token);
			expect(res.status).toBe(200);
			expect(res.data.scope).toBe("read write");
			expect(res.data.scopes).toBeUndefined();
		});

		it("returns 401 for an invalid JWT", async () => {
			const res = await selfIntrospect("invalid.token.here");
			expect(res.status).toBe(401);
			expect(res.data.active).toBe(false);
		});

		it("returns 401 for an expired JWT", async () => {
			const token = jwt.sign({ user: { id: 1 } }, JWT_SECRET, { expiresIn: -1 });
			const res = await selfIntrospect(token);
			expect(res.status).toBe(401);
			expect(res.data.active).toBe(false);
		});
	});

	describe("self-introspect (application/x-www-form-urlencoded)", () => {
		it("returns active: true for a valid JWT", async () => {
			const token = jwt.sign({ user: { id: 1 }, scopes: ["read"] }, JWT_SECRET, {
				expiresIn: 60,
			});
			const res = await selfIntrospect(token, "application/x-www-form-urlencoded");
			expect(res.status).toBe(200);
			expect(res.data.active).toBe(true);
		});

		it("returns 401 for an invalid JWT", async () => {
			const res = await selfIntrospect("invalid.token.here", "application/x-www-form-urlencoded");
			expect(res.status).toBe(401);
			expect(res.data.active).toBe(false);
		});

		it("returns 401 for an expired JWT", async () => {
			const token = jwt.sign({ user: { id: 1 } }, JWT_SECRET, { expiresIn: -1 });
			const res = await selfIntrospect(token, "application/x-www-form-urlencoded");
			expect(res.status).toBe(401);
			expect(res.data.active).toBe(false);
		});
	});
});

describe("POST /session/login", () => {
	it("returns 400 when no credentials are provided", async () => {
		const res = await sessionPost("/session/login", {});
		expect(res.status).toBe(400);
	});

	it("returns 400 when redirect_to has an invalid scheme", async () => {
		const res = await sessionPost("/session/login", {
			username: "testuser",
			password: "testpass",
			redirect_to: "javascript:alert(1)",
		});
		expect(res.status).toBe(400);
		expect(res.data.error).toBe("invalid_redirect");
	});

	it("returns 400 when redirect_to is not a valid URL", async () => {
		const res = await sessionPost("/session/login", {
			username: "testuser",
			password: "testpass",
			redirect_to: "not-a-url",
		});
		expect(res.status).toBe(400);
		expect(res.data.error).toBe("invalid_redirect");
	});

	it("returns 400 when redirect_to exceeds 2048 characters", async () => {
		const res = await sessionPost("/session/login", {
			username: "testuser",
			password: "testpass",
			redirect_to: `https://example.com/${"a".repeat(2048)}`,
		});
		expect(res.status).toBe(400);
		expect(res.data.error).toBe("invalid_redirect");
	});

	it("accepts a valid redirect_to without error", async () => {
		// redirect_to validation runs before authentication, so even with
		// invalid credentials, a valid redirect_to should not cause a 400
		// with error: "invalid_redirect". It should fail with 401 (auth failure).
		const res = await sessionPost("/session/login", {
			username: "testuser",
			password: "testpass",
			redirect_to: "http://localhost:3000/oauth/authorize",
		});
		expect(res.status).not.toBe(400);
		expect(res.data.error).not.toBe("invalid_redirect");
	});
});

describe("CSRF on the state-changing session routes (#272)", () => {
	it("rejects a login carrying neither an origin signal nor a token", async () => {
		// The bypass this replaced: omitting `Origin` skipped the check entirely.
		const res = await client.post("/session/login", {
			username: "testuser",
			password: "testpass",
		});
		expect(res.status).toBe(403);
		expect(res.data.error).toBe("access_denied");
	});

	it("rejects a logout carrying neither an origin signal nor a token", async () => {
		const res = await client.post("/session/logout", {});
		expect(res.status).toBe(403);
		expect(res.data.error).toBe("access_denied");
	});

	it("rejects a login from a foreign origin", async () => {
		const res = await client.post(
			"/session/login",
			{ username: "testuser", password: "testpass" },
			{ headers: { Origin: "https://evil.example.com" } },
		);
		expect(res.status).toBe(403);
	});

	it("accepts a header-less client that presents a token from GET /session/csrf", async () => {
		const issued = await client.get("/session/csrf");
		expect(issued.status).toBe(200);
		expect(typeof issued.data.csrf_token).toBe("string");

		const res = await client.post(
			"/session/login",
			{ username: "testuser", password: "testpass" },
			{
				headers: {
					Cookie: _extractCookies(issued).split(";")[0],
					[issued.data.header_name]: issued.data.csrf_token,
				},
			},
		);
		// Credentials are still wrong in this environment — the point is that the
		// request got past the CSRF guard rather than stopping at 403.
		expect(res.status).not.toBe(403);
	});
});

describe("POST /oauth/token", () => {
	it("returns 401 for grant_type=session without an authenticated session", async () => {
		const res = await client.post("/oauth/token", "grant_type=session", {
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
		});
		expect(res.status).toBe(401);
	});

	it("returns 400 for an unsupported grant_type", async () => {
		const res = await client.post("/oauth/token", "grant_type=unknown", {
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
		});
		expect(res.status).toBe(400);
	});

	it("returns 400 for grant_type=authorization_code without a code", async () => {
		const res = await client.post("/oauth/token", "grant_type=authorization_code", {
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
		});
		expect(res.status).toBe(400);
	});
});

describe("GET /oauth/authorize", () => {
	it("redirects to login with redirect_to when the session is not authenticated", async () => {
		const res = await client.get(
			"/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost:9999/callback",
			{ maxRedirects: 0 },
		);
		expect(res.status).toBe(302);
		const location = res.headers.location;
		expect(location).toContain("login");
		expect(location).toContain("redirect_to=");
		expect(location).not.toContain("redirect_uri=");
		// Verify the authorize URL is properly encoded (? and & should be escaped)
		expect(location).toContain(encodeURIComponent("response_type=code"));
	});
});

describe("GET /session/oauth/federation/google", () => {
	// NOTE: Development config has Google federation disabled (google.enabled: false).
	// The googleEnabled check runs first and returns 404, so redirect_to validation
	// tests cannot run in this environment. Validation logic is identical to
	// POST /session/login and covered by those tests.

	it("returns 404 when Google federation is disabled", async () => {
		const res = await client.get(
			"/session/oauth/federation/google?redirect_to=https://localhost:3001",
		);
		expect(res.status).toBe(404);
	});

	it("returns 404 even with invalid redirect_to when Google is disabled", async () => {
		const res = await client.get(
			"/session/oauth/federation/google?redirect_to=javascript:alert(1)",
		);
		expect(res.status).toBe(404);
	});
});
