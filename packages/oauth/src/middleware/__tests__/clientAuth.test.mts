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

import type { ClientRepository } from "@o3co/auth-provider-core";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createClientAuthMiddleware } from "../clientAuth.mjs";

const fakePublicClient = (clientId: string) => ({
	clientId,
	allowedRedirectUris: [] as string[],
	allowedScopes: [] as string[],
});

const fakeRepo = (creds: Record<string, string>): ClientRepository => ({
	findById: async () => null,
	authenticate: async (id: string, secret: string) => {
		if (creds[id] === secret) return fakePublicClient(id);
		return null;
	},
});

describe("createClientAuthMiddleware", () => {
	it("authenticates via HTTP Basic (RFC 6749 §2.3.1 preferred)", async () => {
		const app = express().use(express.urlencoded({ extended: false }));
		app.post("/test", createClientAuthMiddleware(fakeRepo({ alice: "s3cret" })), (req, res) => {
			res.json({ client: req.oauthClient?.clientId });
		});
		const basic = Buffer.from("alice:s3cret").toString("base64");
		const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
		expect(res.status).toBe(200);
		expect(res.body.client).toBe("alice");
	});

	it("accepts form-encoded client_id/client_secret as a fallback", async () => {
		const app = express().use(express.urlencoded({ extended: false }));
		app.post("/test", createClientAuthMiddleware(fakeRepo({ alice: "s3cret" })), (req, res) => {
			res.json({ client: req.oauthClient?.clientId });
		});
		const res = await request(app)
			.post("/test")
			.type("form")
			.send({ client_id: "alice", client_secret: "s3cret" });
		expect(res.status).toBe(200);
		expect(res.body.client).toBe("alice");
	});

	it("returns 401 with WWW-Authenticate and error_description when credentials are missing", async () => {
		const app = express().use(express.urlencoded({ extended: false }));
		app.post("/test", createClientAuthMiddleware(fakeRepo({})), (_req, res) => res.end());
		const res = await request(app).post("/test");
		expect(res.status).toBe(401);
		expect(res.headers["www-authenticate"]).toMatch(/^Basic realm=/);
		expect(res.body.error).toBe("invalid_client");
		expect(res.body.error_description).toBe("Client authentication is required");
	});

	it("returns 401 invalid_client with error_description when credentials do not match", async () => {
		const app = express().use(express.urlencoded({ extended: false }));
		app.post("/test", createClientAuthMiddleware(fakeRepo({ alice: "s3cret" })), (_req, res) =>
			res.end(),
		);
		const res = await request(app)
			.post("/test")
			.type("form")
			.send({ client_id: "alice", client_secret: "wrong" });
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
		expect(res.body.error_description).toBe("Invalid client credentials");
	});

	it("prefers Basic over form-encoded when both are present", async () => {
		const app = express().use(express.urlencoded({ extended: false }));
		app.post("/test", createClientAuthMiddleware(fakeRepo({ alice: "s3cret" })), (req, res) => {
			res.json({ client: req.oauthClient?.clientId });
		});
		const basic = Buffer.from("alice:s3cret").toString("base64");
		const res = await request(app)
			.post("/test")
			.set("Authorization", `Basic ${basic}`)
			.type("form")
			.send({ client_id: "eve", client_secret: "pwned" });
		expect(res.status).toBe(200);
		expect(res.body.client).toBe("alice");
	});

	it("returns 401 malformed error_description on Basic header with no colon", async () => {
		const app = express().use(express.urlencoded({ extended: false }));
		app.post("/test", createClientAuthMiddleware(fakeRepo({ alice: "s3cret" })), (_req, res) =>
			res.end(),
		);
		// Base64 of a string with no colon
		const malformed = Buffer.from("nocolon").toString("base64");
		const res = await request(app).post("/test").set("Authorization", `Basic ${malformed}`);
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
		expect(res.body.error_description).toBe("Malformed client credentials");
	});

	it("returns 401 fail-closed when clientRepository.authenticate throws — no error_description", async () => {
		const throwingRepo: ClientRepository = {
			findById: async () => null,
			authenticate: async () => {
				throw new Error("store unavailable");
			},
		};
		const app = express().use(express.urlencoded({ extended: false }));
		app.post("/test", createClientAuthMiddleware(throwingRepo), (_req, res) => res.end());
		const basic = Buffer.from("alice:s3cret").toString("base64");
		const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
		// Must NOT leak server-side detail to callers
		expect(res.body.error_description).toBeUndefined();
		expect(JSON.stringify(res.body)).not.toContain("store unavailable");
	});

	// Fix 5: Edge-case tests
	it("returns 401 when client_id has empty secret (client_id:)", async () => {
		const app = express().use(express.urlencoded({ extended: false }));
		app.post("/test", createClientAuthMiddleware(fakeRepo({ alice: "" })), (_req, res) =>
			res.end(),
		);
		// Basic header for "alice:" — empty secret should trip the guard
		const basic = Buffer.from("alice:").toString("base64");
		const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
	});

	it("splits on first colon only — client_id containing colon uses remainder as secret", async () => {
		const authenticateSpy = vi.fn<ClientRepository["authenticate"]>().mockResolvedValue(null);
		const spyRepo: ClientRepository = { authenticate: authenticateSpy, findById: vi.fn() };
		const app = express().use(express.urlencoded({ extended: false }));
		app.post("/test", createClientAuthMiddleware(spyRepo), (_req, res) => res.end());
		// Base64 of "a:b:c:d" — clientId should be "a", secret "b:c:d"
		const basic = Buffer.from("a:b:c:d").toString("base64");
		const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
		expect(res.status).toBe(401);
		expect(authenticateSpy).toHaveBeenCalledWith("a", "b:c:d");
	});

	it("URL-decodes percent-encoded credentials from Basic header", async () => {
		const authenticateSpy = vi
			.fn<ClientRepository["authenticate"]>()
			.mockResolvedValue(fakePublicClient("client_id@example"));
		const spyRepo: ClientRepository = { authenticate: authenticateSpy, findById: vi.fn() };
		const app = express().use(express.urlencoded({ extended: false }));
		app.post("/test", createClientAuthMiddleware(spyRepo), (req, res) => {
			res.json({ client: req.oauthClient?.clientId });
		});
		// Base64 of "client_id%40example:secret%20with%20space"
		const basic = Buffer.from("client_id%40example:secret%20with%20space").toString("base64");
		const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
		expect(res.status).toBe(200);
		expect(authenticateSpy).toHaveBeenCalledWith("client_id@example", "secret with space");
		expect(res.body.client).toBe("client_id@example");
	});

	it("returns 401 Client authentication is required when no credentials in body or header", async () => {
		const app = express().use(express.urlencoded({ extended: false }));
		app.post("/test", createClientAuthMiddleware(fakeRepo({})), (_req, res) => res.end());
		// POST with no Authorization header, no client_id, no client_secret
		const res = await request(app).post("/test").type("form").send({});
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
		expect(res.body.error_description).toBe("Client authentication is required");
	});

	// Fix 5: RFC 6749 §2.3.1 — `+` in Basic credentials must decode to space (x-www-form-urlencoded)
	it("Fix 5: Basic auth with + in credentials decodes to space (RFC 6749 §2.3.1 x-www-form-urlencoded)", async () => {
		const authenticateSpy = vi
			.fn<ClientRepository["authenticate"]>()
			.mockResolvedValue(fakePublicClient("alice"));
		const spyRepo: ClientRepository = { authenticate: authenticateSpy, findById: vi.fn() };
		const app = express().use(express.urlencoded({ extended: false }));
		app.post("/test", createClientAuthMiddleware(spyRepo), (req, res) => {
			res.json({ client: req.oauthClient?.clientId });
		});
		// "alice:with+space" — `+` represents a literal space per x-www-form-urlencoded
		const basic = Buffer.from("alice:with+space").toString("base64");
		const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
		expect(res.status).toBe(200);
		expect(authenticateSpy).toHaveBeenCalledWith("alice", "with space");
		expect(res.body.client).toBe("alice");
	});

	// Fix 6: decodeURIComponent throw path
	it("returns 401 Malformed client credentials when Basic header contains invalid percent-encoding", async () => {
		const app = express().use(express.urlencoded({ extended: false }));
		app.post("/test", createClientAuthMiddleware(fakeRepo({})), (_req, res) => res.end());
		// "%zz" is invalid URL-encoding — decodeURIComponent will throw
		// Buffer.from preserves the literal bytes through base64 round-trip
		const basic = Buffer.from("%zz:x").toString("base64");
		const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
		expect(res.body.error_description).toBe("Malformed client credentials");
	});
});
