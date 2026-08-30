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

import { createSecretKey } from "node:crypto";
import {
	type AuditEvent,
	type AuditSink,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	defineModule,
	jwksModule,
	memoryAccessTokenDenylistModule,
	type RefreshTokenFamilyRevocation,
} from "@o3co/auth-provider-core";
import { createTestApp, GrantRegistry, makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { oauthModule } from "#/module.mjs";
import { createOAuthRouter } from "#/routes.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const mockConfig = {
	oauth: {
		jwt: { issuer: "https://auth.example" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {},
	},
	endpoints: {
		login: { url: "/login" },
	},
} as unknown as import("@o3co/auth-provider-core").AppConfig;

const mockClientRepository: ClientRepository = {
	findById: async () => null,
	authenticate: async () => null,
};

const mockCodeRepository: CodeRepository = {
	// D-1: Code requires client_id + redirect_uri.
	createCode: async () => ({
		code: "test-code",
		client_id: "client1",
		redirect_uri: "https://rp.example/cb",
	}),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

async function makeAccessToken(overrides: Record<string, unknown> = {}): Promise<string> {
	return new SignJWT({ sub: "u1", scope: "read", ...overrides })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "at+jwt" })
		.setIssuer("https://auth.example")
		.setExpirationTime("1h")
		.sign(secretKey);
}

async function buildApp(
	refreshTokenFamilyRevocation?: RefreshTokenFamilyRevocation,
	auditSink?: AuditSink,
) {
	const app = express();
	app.set("trust proxy", 1);
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));

	const { router } = await createOAuthRouter(express, {
		registry: new GrantRegistry(),
		config: mockConfig,
		clientRepository: mockClientRepository,
		codeRepository: mockCodeRepository,
		keyStore,
		refreshTokenFamilyRevocation,
		auditSink,
	});

	app.use("/oauth", router);
	return app;
}

// Use the Bearer self-introspection path: Bearer token == body token.
// RFC 7662 §2.1 allows the resource server (or the client itself) to send
// the same token as the Bearer credential — the introspect handler validates
// that the body.token matches the Authorization header token, then proceeds.
async function introspect(app: ReturnType<typeof express>, token: string) {
	return request(app)
		.post("/oauth/introspect")
		.set("Authorization", `Bearer ${token}`)
		.send({ token });
}

describe("/introspect — family revoke cascade (TODO-F-3 task 5)", () => {
	it("returns active:true when family_id present and isFamilyRevoked returns false", async () => {
		const familyId = "fam-abc";
		const token = await makeAccessToken({ family_id: familyId });

		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockResolvedValue(false),
		};

		const app = await buildApp(refreshTokenFamilyRevocation);
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(refreshTokenFamilyRevocation.isFamilyRevoked).toHaveBeenCalledWith(familyId);
	});

	it("returns active:false when family_id present and isFamilyRevoked returns true", async () => {
		const familyId = "fam-revoked";
		const token = await makeAccessToken({ family_id: familyId });

		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockResolvedValue(true),
		};

		const app = await buildApp(refreshTokenFamilyRevocation);
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
	});

	it("returns active:false (fail-closed) when isFamilyRevoked throws", async () => {
		const familyId = "fam-error";
		const token = await makeAccessToken({ family_id: familyId });

		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockRejectedValue(new Error("store unavailable")),
		};

		const app = await buildApp(refreshTokenFamilyRevocation);
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
	});

	it("emits introspect.store_unavailable audit event when isFamilyRevoked throws", async () => {
		const familyId = "fam-error-audit";
		const token = await makeAccessToken({ family_id: familyId });

		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockRejectedValue(new Error("backend down")),
		};
		const events: AuditEvent[] = [];
		const auditSink: AuditSink = {
			kind: "spy",
			async record(event) {
				events.push(event);
			},
		};

		const app = await buildApp(refreshTokenFamilyRevocation, auditSink);
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
		const storeEvent = events.find((e) => e.type === "introspect.store_unavailable");
		expect(storeEvent).toBeDefined();
		expect((storeEvent?.details as Record<string, unknown>)?.family_id).toBe(familyId);
		expect((storeEvent?.details as Record<string, unknown>)?.error).toContain("backend down");
	});

	it("emits introspect.family_revoked audit event when family is revoked", async () => {
		const familyId = "fam-revoked-audit";
		const token = await makeAccessToken({ family_id: familyId });

		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockResolvedValue(true),
		};
		const events: AuditEvent[] = [];
		const auditSink: AuditSink = {
			kind: "spy",
			async record(event) {
				events.push(event);
			},
		};

		const app = await buildApp(refreshTokenFamilyRevocation, auditSink);
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
		const revokedEvent = events.find((e) => e.type === "introspect.family_revoked");
		expect(revokedEvent).toBeDefined();
		expect((revokedEvent?.details as Record<string, unknown>)?.family_id).toBe(familyId);
	});

	it("returns active:true and does NOT consult store for legacy token without family_id", async () => {
		const token = await makeAccessToken(); // no family_id claim

		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
			revokeFamily: vi.fn(),
			// Throws if called — ensures no consultation for legacy tokens
			isFamilyRevoked: vi.fn().mockImplementation(() => {
				throw new Error("isFamilyRevoked must not be called for legacy tokens");
			}),
		};

		const app = await buildApp(refreshTokenFamilyRevocation);
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(refreshTokenFamilyRevocation.isFamilyRevoked).not.toHaveBeenCalled();
	});

	it("rejects empty-string family_id and does NOT consult store", async () => {
		// family_id: "" should be treated as missing (M1 guard)
		const token = await makeAccessToken({ family_id: "" });

		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockImplementation(() => {
				throw new Error("isFamilyRevoked must not be called for empty family_id");
			}),
		};

		const app = await buildApp(refreshTokenFamilyRevocation);
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(refreshTokenFamilyRevocation.isFamilyRevoked).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// SF-8: /introspect token_type + access-only enforcement (RFC 7662 §2.2)
//
// Pre-SF-8, /introspect echoed the JOSE `typ` header value (e.g. "at+jwt") in
// `token_type` — wrong namespace per RFC 7662 (which references the OAuth
// Token Type registry, not JOSE). It also accepted RT / id_token JWTs as
// `active: true` since the verifier was signature-only. SF-8 hardcodes
// `token_type: "Bearer"` for active access tokens and relies on SF-1's typ
// pin to filter non-access tokens to `{ active: false }`.
// ---------------------------------------------------------------------------

describe("/introspect — SF-8: token_type + access-only enforcement", () => {
	async function makeRefreshToken(overrides: Record<string, unknown> = {}): Promise<string> {
		return new SignJWT({ sub: "u1", scope: "read", ...overrides })
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
			.setIssuer("https://auth.example")
			.setExpirationTime("1h")
			.sign(secretKey);
	}

	async function makeIdToken(overrides: Record<string, unknown> = {}): Promise<string> {
		return new SignJWT({ sub: "u1", aud: "client1", ...overrides })
			.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "id+jwt" })
			.setIssuer("https://auth.example")
			.setExpirationTime("1h")
			.sign(secretKey);
	}

	it("RED-1: returns active=true with token_type=Bearer + jti for a valid access token (NOT 'at+jwt')", async () => {
		// RFC 6750 §6.1.1 — `Bearer` is the OAuth Token Type. The pre-SF-8
		// response leaked the JOSE `typ` ("at+jwt"), wrong namespace per
		// RFC 7662 §2.2. RFC 7662 §2.2 also lists `jti` as a registered
		// response field (Codex calibration m3) — confirm presence.
		const token = await makeAccessToken({ client_id: "client1", jti: "jti-sf8-red1" });
		const app = await buildApp();
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(res.body.token_type).toBe("Bearer");
		expect(res.body.token_type).not.toBe("at+jwt");
		expect(res.body.jti).toBe("jti-sf8-red1");
	});

	it("RED-2: returns active=false for a refresh token (no leak of RT validity)", async () => {
		// RFC 7662 §2.1 + OAuth Security Topics §5.1: introspection is for
		// access tokens only. A valid RT MUST return active:false to prevent
		// a resource server from probing RT validity via the introspect
		// endpoint.
		const token = await makeRefreshToken();
		const app = await buildApp();
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
		expect(res.body.token_type).toBeUndefined();
	});

	it("RED-3: returns active=false for an id_token", async () => {
		// Same RFC 7662 §2.1 reasoning as RT: id_tokens are not introspectable
		// access tokens; treating them as active leaks information.
		const token = await makeIdToken();
		const app = await buildApp();
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
	});

	it("RED-4: response carries client_id (RFC 7662 §2.2 RECOMMENDED) — sourced from client_id when present, falls back to azp for v0.5.1 compat", async () => {
		// Codex calibration m2: current issuance emits `azp` (RFC 9068 §2.2),
		// not `client_id`. RFC 7662 §2.2 lists `client_id` as RECOMMENDED in
		// the response. SF-8 returns `client_id: payload.client_id ?? azp`
		// so resource servers see the authorized-party identifier under the
		// standard field name regardless of which side of the v0.5/v0.6
		// upgrade window the issuance is on. v0.6+ flips issuance to emit
		// `client_id` directly; this fallback becomes a no-op then.
		const token = await makeAccessToken({ azp: "client1" });
		const app = await buildApp();
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(res.body.client_id).toBe("client1");
	});

	it("TD-5: active access-token response carries RFC 7662 fields without leaking family_id", async () => {
		const token = await makeAccessToken({
			sub: "user-td5",
			aud: "https://resource.example",
			azp: "client-td5",
			scope: "openid profile",
			iat: 1_772_000_000,
			jti: "jti-td5",
			family_id: "family-internal",
		});
		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockResolvedValue(false),
		};
		const app = await buildApp(refreshTokenFamilyRevocation);
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({
			active: true,
			iss: "https://auth.example",
			aud: "https://resource.example",
			sub: "user-td5",
			azp: "client-td5",
			client_id: "client-td5",
			scope: "openid profile",
			token_type: "Bearer",
			jti: "jti-td5",
			iat: 1_772_000_000,
		});
		expect(typeof res.body.exp).toBe("number");
		expect(res.body.family_id).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// oauthModule — refreshTokenFamilyRevocation composition (C1) via createTestApp
//
// Migrated to createTestApp pattern: oauthModule is booted via the Phase 4
// planner; refreshTokenFamilyRevocation flows through the DI graph. The
// family-revoke cascade must still fire because createOAuthRouter receives the
// store from typed deps (A3 §5.3 — RefreshTokenFamilyRevocation interface).
// ---------------------------------------------------------------------------

describe("oauthModule — refreshTokenFamilyRevocation composition (C1) via createTestApp", () => {
	it("threads refreshTokenFamilyRevocation through to /introspect so family revocation returns active:false", async () => {
		const familyId = "fam-module-revoked";
		const token = await makeAccessToken({ family_id: familyId });

		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockResolvedValue(true),
		};

		// refreshTokenFamilyRevocation flows through the DI graph as the A3 §5.3 slot;
		// oauthModule reads it from typed deps and forwards to createOAuthRouter.
		const refreshTokenFamilyRevocationModule = defineModule({
			name: "test:refresh-token-family-revocation",
			provides: { refreshTokenFamilyRevocation: () => refreshTokenFamilyRevocation },
		});

		const base = makeValidAppConfig();
		const config = {
			...base,
			oauth: {
				...base.oauth,
				jwt: { ...base.oauth.jwt, issuer: "https://auth.example" },
			},
		};

		const keyStoreForC1 = defineModule({
			name: "test:key-store-c1",
			provides: { keyStore: () => createSymmetricKeyStore(SECRET) },
		});
		const clientRepositoryModule = defineModule({
			name: "test:client-repository-c1",
			provides: { clientRepository: () => mockClientRepository },
		});
		const codeRepositoryModule = defineModule({
			name: "test:code-repository-c1",
			provides: { codeRepository: () => mockCodeRepository },
		});

		const handle = await createTestApp({
			modules: [
				oauthModule({ config }),
				// #277: oauthModule mounts /oauth/revoke, so the boot validator requires a
				// denylist behind it. Memory is right here — one process, one test.
				memoryAccessTokenDenylistModule,
				// Issuer is configured, so the discovery presence contract requires
				// the JWKS-owning module (contributes jwks_uri) to be co-installed.
				jwksModule,
				clientRepositoryModule,
				codeRepositoryModule,
				keyStoreForC1,
				refreshTokenFamilyRevocationModule,
			],
			bootstrapComponents: { config, pathResolver: (s) => s },
		});

		const app = express();
		app.set("trust proxy", 1);
		app.use(express.json());
		app.use(express.urlencoded({ extended: false }));
		for (const route of handle.inspect.routes) {
			app.use(route.contribution.mountPath, route.contribution.handler);
		}

		const res = await introspect(app, token);

		// If C1 is fixed, the store was consulted and the family is revoked → inactive.
		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
		expect(refreshTokenFamilyRevocation.isFamilyRevoked).toHaveBeenCalledWith(familyId);

		await handle.dispose();
	});
});

/*
 * #318 — introspection describes the TOKEN, and stays that way.
 *
 * #297 asked for `email_verified` in the id_token, `/userinfo` and
 * introspection. The first two ship; the third was split out because it is a
 * design decision, not a gap. The decision is **no**, and this pins it as an
 * invariant rather than leaving it as prose someone has to find.
 *
 * RFC 7662 §2.2 defines the response as meta-information about the token, and
 * §5 is explicit about the cost of going further: *"Omitting privacy-sensitive
 * information from an introspection response is the simplest way of minimizing
 * privacy issues"*, alongside a `MUST` to prevent disclosure of user
 * identifiers to unintended parties. §2.2 carries the same instinct for scopes
 * — an AS "MAY limit which scopes from a given token are returned for each
 * protected resource to prevent a protected resource from learning more about
 * the larger network than necessary."
 *
 * Both ways to answer differently have a real cost, and neither buys anything
 * `/userinfo` does not already give a resource server holding the token:
 * minting user claims into every access token spreads PII into a credential
 * that transits more places than an id_token and goes stale the moment the
 * Store flips it (access tokens are not re-derived); reading the session store
 * from the introspect handler turns a session-store outage into an
 * introspection outage, on a hot path resource servers call per request.
 *
 * So the guard is the deliverable: a token whose subject has user claims in
 * the Store still introspects to token metadata alone. A future change that
 * makes introspection a second `/userinfo` fails here and has to argue with
 * this comment first.
 */
describe("/introspect carries token metadata only (#318)", () => {
	/**
	 * Exactly what this AS answers with — an RFC 7662 §2.2 **subset plus two
	 * extensions**, not the §2.2 set:
	 *
	 * - `username` and `nbf` are §2.2 members deliberately omitted (this AS
	 *   issues `at+jwt` without `nbf` and does not persist a human-readable
	 *   username — see `IntrospectResponse`).
	 * - `azp` is not a §2.2 member; it mirrors RFC 9068's authorized-party
	 *   claim.
	 * - `cnf` is the confirmation mirror the token-binding work added.
	 *
	 * §2.2 permits both directions — every member is optional, and
	 * "implementations MAY extend this structure with their own
	 * service-specific response names". Naming the set precisely matters here
	 * because the point of the guard is that it is a closed list: calling it
	 * "the RFC set" would invite adding a §2.2 member (`username`) that this AS
	 * has decided not to answer.
	 */
	const ALLOWED = new Set([
		"active",
		"exp",
		"iat",
		"iss",
		"aud",
		"sub",
		"azp",
		"client_id",
		"scope",
		"token_type",
		"jti",
		"cnf",
	]);

	it("returns no member outside the closed set this AS answers", async () => {
		const token = await makeAccessToken({ client_id: "client1", jti: "jti-318" });
		const app = await buildApp();
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		const unexpected = Object.keys(res.body).filter((k) => !ALLOWED.has(k));
		expect(unexpected).toEqual([]);
	});

	it("does not carry email_verified — the claim #318 asked about", async () => {
		const token = await makeAccessToken({ client_id: "client1" });
		const app = await buildApp();
		const res = await introspect(app, token);

		expect(res.body.email_verified).toBeUndefined();
		expect(res.body.email).toBeUndefined();
	});

	it("does not echo user claims that a token happens to carry", async () => {
		// The other direction: even if something upstream minted profile claims
		// into an access token, introspection must not forward them. Otherwise
		// the invariant would hold only for as long as minting stays clean.
		const token = await makeAccessToken({
			client_id: "client1",
			email: "alice@example.com",
			email_verified: true,
			name: "Alice Example",
		});
		const app = await buildApp();
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		const unexpected = Object.keys(res.body).filter((k) => !ALLOWED.has(k));
		expect(unexpected).toEqual([]);
	});

	it("says nothing at all beyond active=false for an inactive token", async () => {
		// RFC 7662 §2.2: an inactive response must not reveal why. A leaked
		// `sub` here would tell a caller the token existed.
		const app = await buildApp();
		const res = await introspect(app, "not-a-token");

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ active: false });
	});
});
