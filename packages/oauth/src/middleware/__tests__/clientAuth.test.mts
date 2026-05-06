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

import type {
	ClientRepository,
	PublicClient,
	TokenEndpointAuthMethod,
} from "@o3co/auth-provider-core";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createClientAuthMiddleware } from "../clientAuth.mjs";

interface FakeClient {
	clientId: string;
	tokenEndpointAuthMethod: TokenEndpointAuthMethod;
	clientSecret?: string;
}

const buildPublicClient = (c: FakeClient): PublicClient => ({
	clientId: c.clientId,
	tokenEndpointAuthMethod: c.tokenEndpointAuthMethod,
	allowedRedirectUris: [],
	allowedScopes: [],
});

/**
 * Test repository that supports both confidential (basic / post) and public
 * (`"none"`) clients. After D-6, `clientAuthMw` calls `findById` to obtain the
 * configured `tokenEndpointAuthMethod`, then `authenticate` for confidential
 * clients only — so tests must populate both methods consistently.
 */
const fakeRepo = (clients: FakeClient[]): ClientRepository => {
	const byId = new Map(clients.map((c) => [c.clientId, c]));
	return {
		findById: async (clientId) => {
			const c = byId.get(clientId);
			return c ? buildPublicClient(c) : null;
		},
		authenticate: async (clientId, secret) => {
			const c = byId.get(clientId);
			if (!c) return null;
			if (c.tokenEndpointAuthMethod === "none") return null;
			if (c.clientSecret !== secret) return null;
			return buildPublicClient(c);
		},
	};
};

const basicConfidential = (clientId: string, secret: string): FakeClient => ({
	clientId,
	tokenEndpointAuthMethod: "client_secret_basic",
	clientSecret: secret,
});

const postConfidential = (clientId: string, secret: string): FakeClient => ({
	clientId,
	tokenEndpointAuthMethod: "client_secret_post",
	clientSecret: secret,
});

const publicClient = (clientId: string): FakeClient => ({
	clientId,
	tokenEndpointAuthMethod: "none",
});

describe("createClientAuthMiddleware (D-6 PB-2)", () => {
	describe("group B-1..B-9 — confidential + public client paths", () => {
		it("B-1: no credentials at all → 401 invalid_client + WWW-Authenticate", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post("/test", createClientAuthMiddleware(fakeRepo([])), (_req, res) => res.end());
			const res = await request(app).post("/test").type("form").send({});
			expect(res.status).toBe(401);
			expect(res.headers["www-authenticate"]).toMatch(/^Basic realm=/);
			expect(res.body.error).toBe("invalid_client");
			expect(res.body.error_description).toBe("Client authentication is required");
		});

		it("B-2: valid Basic for a client_secret_basic client → next() with req.oauthClient set", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([basicConfidential("alice", "s3cret")])),
				(req, res) => {
					res.json({
						client: req.oauthClient?.clientId,
						method: req.oauthClient?.tokenEndpointAuthMethod,
					});
				},
			);
			const basic = Buffer.from("alice:s3cret").toString("base64");
			const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
			expect(res.status).toBe(200);
			expect(res.body.client).toBe("alice");
			expect(res.body.method).toBe("client_secret_basic");
		});

		it("B-3: wrong secret in Basic → 401 invalid_client + WWW-Authenticate", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([basicConfidential("alice", "s3cret")])),
				(_req, res) => res.end(),
			);
			const basic = Buffer.from("alice:wrong").toString("base64");
			const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
			expect(res.status).toBe(401);
			expect(res.headers["www-authenticate"]).toMatch(/^Basic realm=/);
			expect(res.body.error).toBe("invalid_client");
			expect(res.body.error_description).toBe("Invalid client credentials");
		});

		it("B-4: malformed Basic (no colon) → 401 invalid_client + WWW-Authenticate", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([basicConfidential("alice", "s3cret")])),
				(_req, res) => res.end(),
			);
			const malformed = Buffer.from("nocolon").toString("base64");
			const res = await request(app).post("/test").set("Authorization", `Basic ${malformed}`);
			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_client");
			expect(res.body.error_description).toBe("Malformed client credentials");
		});

		it("B-5: form-encoded credentials for client_secret_post client → next()", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([postConfidential("alice", "s3cret")])),
				(req, res) => res.json({ client: req.oauthClient?.clientId }),
			);
			const res = await request(app)
				.post("/test")
				.type("form")
				.send({ client_id: "alice", client_secret: "s3cret" });
			expect(res.status).toBe(200);
			expect(res.body.client).toBe("alice");
		});

		it("B-6: public client supplies only client_id in body → next() with public method (when allowPublicClients=true)", async () => {
			// `/oauth/token` admits public clients (PKCE/S256 enforces authenticity
			// at `/oauth/authorize`). Other routes leave `allowPublicClients` at
			// the default `false` and would reject — see the dedicated P1 group.
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([publicClient("spa")]), { allowPublicClients: true }),
				(req, res) => {
					res.json({
						client: req.oauthClient?.clientId,
						method: req.oauthClient?.tokenEndpointAuthMethod,
					});
				},
			);
			const res = await request(app).post("/test").type("form").send({ client_id: "spa" });
			expect(res.status).toBe(200);
			expect(res.body.client).toBe("spa");
			expect(res.body.method).toBe("none");
		});

		it("B-7: confidential client called with body client_id only (no secret) → 401, no WWW-Authenticate (body attempt)", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([basicConfidential("alice", "s3cret")])),
				(_req, res) => res.end(),
			);
			const res = await request(app).post("/test").type("form").send({ client_id: "alice" });
			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_client");
			// Body-only attempt → no Basic challenge in response.
			expect(res.headers["www-authenticate"]).toBeUndefined();
		});

		it("B-8: unknown client → 401 invalid_client", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post("/test", createClientAuthMiddleware(fakeRepo([])), (_req, res) => res.end());
			const res = await request(app).post("/test").type("form").send({ client_id: "ghost" });
			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_client");
			expect(res.body.error_description).toBe("Unknown client");
		});

		it("B-9: Basic auth + body matching client_id (no body secret) → next() with Basic credentials used", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([basicConfidential("alice", "s3cret")])),
				(req, res) => res.json({ client: req.oauthClient?.clientId }),
			);
			const basic = Buffer.from("alice:s3cret").toString("base64");
			const res = await request(app)
				.post("/test")
				.set("Authorization", `Basic ${basic}`)
				.type("form")
				.send({ client_id: "alice" });
			expect(res.status).toBe(200);
			expect(res.body.client).toBe("alice");
		});
	});

	describe("Codex M4 — Basic+body conflict detection (B-10)", () => {
		it("B-10a: Basic alice + body eve → 401 client_id mismatch", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(
					fakeRepo([basicConfidential("alice", "s3cret"), basicConfidential("eve", "pwned")]),
				),
				(_req, res) => res.end(),
			);
			const basic = Buffer.from("alice:s3cret").toString("base64");
			const res = await request(app)
				.post("/test")
				.set("Authorization", `Basic ${basic}`)
				.type("form")
				.send({ client_id: "eve", client_secret: "pwned" });
			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_client");
			expect(res.body.error_description).toBe("client_id mismatch between Basic header and body");
		});

		it("B-10b: Basic alice:s3cret + body alice:wrong → 401 client_secret mismatch", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([basicConfidential("alice", "s3cret")])),
				(_req, res) => res.end(),
			);
			const basic = Buffer.from("alice:s3cret").toString("base64");
			const res = await request(app)
				.post("/test")
				.set("Authorization", `Basic ${basic}`)
				.type("form")
				.send({ client_id: "alice", client_secret: "wrong" });
			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_client");
			expect(res.body.error_description).toBe(
				"client_secret mismatch between Basic header and body",
			);
		});
	});

	describe("Codex M1 — per-method enforcement (B-method-1, B-method-2)", () => {
		it("B-method-1: client configured 'client_secret_basic' rejects body credentials", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([basicConfidential("alice", "s3cret")])),
				(_req, res) => res.end(),
			);
			const res = await request(app)
				.post("/test")
				.type("form")
				.send({ client_id: "alice", client_secret: "s3cret" });
			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_client");
			expect(res.body.error_description).toMatch(/tokenEndpointAuthMethod mismatch/);
		});

		it("B-method-2: client configured 'client_secret_post' rejects HTTP Basic credentials", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([postConfidential("alice", "s3cret")])),
				(_req, res) => res.end(),
			);
			const basic = Buffer.from("alice:s3cret").toString("base64");
			const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_client");
			expect(res.body.error_description).toMatch(/tokenEndpointAuthMethod mismatch/);
			expect(res.headers["www-authenticate"]).toMatch(/^Basic realm=/);
		});

		it("B-method-3: confidential client called as if public (no secret) → mismatch", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([basicConfidential("confidential-rp", "s3cret")])),
				(_req, res) => res.end(),
			);
			const res = await request(app)
				.post("/test")
				.type("form")
				.send({ client_id: "confidential-rp" });
			expect(res.status).toBe(401);
			expect(res.body.error_description).toMatch(/Client authentication is required/);
		});
	});

	describe("repository fail-closed", () => {
		it("returns 401 fail-closed when findById throws — no error_description leak", async () => {
			const throwingRepo: ClientRepository = {
				findById: async () => {
					throw new Error("store unavailable");
				},
				authenticate: async () => null,
			};
			const app = express().use(express.urlencoded({ extended: false }));
			app.post("/test", createClientAuthMiddleware(throwingRepo), (_req, res) => res.end());
			const basic = Buffer.from("alice:s3cret").toString("base64");
			const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_client");
			expect(res.body.error_description).toBeUndefined();
			expect(JSON.stringify(res.body)).not.toContain("store unavailable");
		});

		it("returns 401 fail-closed when authenticate throws — no error_description leak", async () => {
			const throwingRepo: ClientRepository = {
				findById: async (id) =>
					id === "alice" ? buildPublicClient(basicConfidential("alice", "s3cret")) : null,
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
			expect(res.body.error_description).toBeUndefined();
		});
	});

	describe("Basic header parsing edge cases", () => {
		it("returns 401 when Basic credentials have empty secret (alice:)", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			// alice has tokenEndpointAuthMethod=basic but no secret matches "" — the
			// authenticate path returns null; per-method gate accepts the basic
			// transport since it was attempted.
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([basicConfidential("alice", "")])),
				(_req, res) => res.end(),
			);
			const basic = Buffer.from("alice:").toString("base64");
			const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_client");
		});

		it("splits on first colon only — secret may contain colons", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			const repo = fakeRepo([basicConfidential("a", "b:c:d")]);
			const authSpy = vi.spyOn(repo, "authenticate");
			app.post("/test", createClientAuthMiddleware(repo), (req, res) => {
				res.json({ client: req.oauthClient?.clientId });
			});
			const basic = Buffer.from("a:b:c:d").toString("base64");
			const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
			expect(res.status).toBe(200);
			expect(authSpy).toHaveBeenCalledWith("a", "b:c:d");
			expect(res.body.client).toBe("a");
		});

		it("URL-decodes percent-encoded credentials from Basic header", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			const repo = fakeRepo([basicConfidential("client_id@example", "secret with space")]);
			const authSpy = vi.spyOn(repo, "authenticate");
			app.post("/test", createClientAuthMiddleware(repo), (req, res) => {
				res.json({ client: req.oauthClient?.clientId });
			});
			const basic = Buffer.from("client_id%40example:secret%20with%20space").toString("base64");
			const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
			expect(res.status).toBe(200);
			expect(authSpy).toHaveBeenCalledWith("client_id@example", "secret with space");
			expect(res.body.client).toBe("client_id@example");
		});

		it("Basic auth with `+` decodes to space (RFC 6749 §2.3.1 x-www-form-urlencoded)", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			const repo = fakeRepo([basicConfidential("alice", "with space")]);
			const authSpy = vi.spyOn(repo, "authenticate");
			app.post("/test", createClientAuthMiddleware(repo), (req, res) => {
				res.json({ client: req.oauthClient?.clientId });
			});
			const basic = Buffer.from("alice:with+space").toString("base64");
			const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
			expect(res.status).toBe(200);
			expect(authSpy).toHaveBeenCalledWith("alice", "with space");
		});

		it("Authorization scheme is case-insensitive (lowercase 'basic')", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([basicConfidential("alice", "s3cret")])),
				(req, res) => res.json({ client: req.oauthClient?.clientId }),
			);
			const creds = Buffer.from("alice:s3cret").toString("base64");
			const res = await request(app).post("/test").set("Authorization", `basic ${creds}`);
			expect(res.status).toBe(200);
			expect(res.body.client).toBe("alice");
		});

		it("Authorization scheme is case-insensitive (uppercase 'BASIC')", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([basicConfidential("alice", "s3cret")])),
				(req, res) => res.json({ client: req.oauthClient?.clientId }),
			);
			const creds = Buffer.from("alice:s3cret").toString("base64");
			const res = await request(app).post("/test").set("Authorization", `BASIC ${creds}`);
			expect(res.status).toBe(200);
			expect(res.body.client).toBe("alice");
		});

		it("returns 401 Malformed when Basic header contains invalid percent-encoding", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post("/test", createClientAuthMiddleware(fakeRepo([])), (_req, res) => res.end());
			// "%zz" is invalid URL-encoding — decodeURIComponent will throw
			const basic = Buffer.from("%zz:x").toString("base64");
			const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_client");
			expect(res.body.error_description).toBe("Malformed client credentials");
		});
	});

	describe("P1 (Codex post-review): allowPublicClients gates the public-client path", () => {
		it("default (allowPublicClients omitted) rejects public clients with 401 invalid_client", async () => {
			// /oauth/introspect (RFC 7662 §2.1) and any non-/token route MUST
			// reject public clients — knowledge of a client_id is not a credential.
			const app = express().use(express.urlencoded({ extended: false }));
			app.post("/test", createClientAuthMiddleware(fakeRepo([publicClient("spa")])), (_req, res) =>
				res.end(),
			);
			const res = await request(app).post("/test").type("form").send({ client_id: "spa" });
			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_client");
			expect(res.body.error_description).toMatch(/Public clients are not allowed/);
		});

		it("allowPublicClients: false also rejects (explicit form)", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([publicClient("spa")]), { allowPublicClients: false }),
				(_req, res) => res.end(),
			);
			const res = await request(app).post("/test").type("form").send({ client_id: "spa" });
			expect(res.status).toBe(401);
			expect(res.body.error_description).toMatch(/Public clients are not allowed/);
		});

		it("allowPublicClients: true accepts public clients (used by /oauth/token only)", async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([publicClient("spa")]), { allowPublicClients: true }),
				(req, res) => res.json({ client: req.oauthClient?.clientId }),
			);
			const res = await request(app).post("/test").type("form").send({ client_id: "spa" });
			expect(res.status).toBe(200);
			expect(res.body.client).toBe("spa");
		});
	});

	describe("issuer-driven WWW-Authenticate realm", () => {
		it('emits realm="<issuer>" when issuer option is provided', async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post(
				"/test",
				createClientAuthMiddleware(fakeRepo([]), { issuer: "https://issuer.example" }),
				(_req, res) => res.end(),
			);
			const res = await request(app).post("/test");
			expect(res.headers["www-authenticate"]).toBe('Basic realm="https://issuer.example"');
		});

		it('falls back to realm="oauth" when issuer is unset', async () => {
			const app = express().use(express.urlencoded({ extended: false }));
			app.post("/test", createClientAuthMiddleware(fakeRepo([])), (_req, res) => res.end());
			const res = await request(app).post("/test");
			expect(res.headers["www-authenticate"]).toBe('Basic realm="oauth"');
		});

		it("backward-compat: accepts a Logger argument directly", async () => {
			// F1 D-4 callers passed `Logger` as the second argument; the new signature
			// takes an options object but keeps the legacy form working.
			const calls: { ctx: unknown; msg?: string }[] = [];
			const logger = {
				debug: () => {},
				info: () => {},
				warn: (ctx: unknown, msg?: string) => {
					calls.push({ ctx, msg });
				},
				error: () => {},
				fatal: () => {},
				child: () => logger,
			};
			const throwingRepo: ClientRepository = {
				findById: async () => {
					throw new Error("store down");
				},
				authenticate: async () => null,
			};
			const app = express().use(express.urlencoded({ extended: false }));
			app.post("/test", createClientAuthMiddleware(throwingRepo, logger), (_req, res) => res.end());
			const basic = Buffer.from("alice:s3cret").toString("base64");
			const res = await request(app).post("/test").set("Authorization", `Basic ${basic}`);
			expect(res.status).toBe(401);
			expect(calls.length).toBeGreaterThan(0);
		});
	});
});
