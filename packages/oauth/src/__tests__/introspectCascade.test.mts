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
import {
	createTestApp,
	GrantRegistry,
	makeValidAppConfig,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { oauthModule } from "#/module.mjs";
import { createOAuthRouter } from "#/routes.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { withOauthCaptures } from "./_helpers/sections.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const mockConfig = {
	oauth: {
		jwt: { issuer: "https://auth.example" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
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
	// A code record requires client_id + redirect_uri.
	createCode: async () =>
		codeRecord({
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
		requirements: resolverForTests([]),
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

describe("/introspect — family revoke cascade", () => {
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

	it("returns 503 (fail-closed, not a verdict on the token) when isFamilyRevoked throws", async () => {
		const familyId = "fam-error";
		const token = await makeAccessToken({ family_id: familyId });

		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockRejectedValue(new Error("store unavailable")),
		};

		const app = await buildApp(refreshTokenFamilyRevocation);
		const res = await introspect(app, token);

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "refresh token store unavailable",
		});
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

		expect(res.status).toBe(503);
		const storeEvent = events.find((e) => e.type === "introspect.store_unavailable");
		expect(storeEvent).toBeDefined();
		expect((storeEvent?.details as Record<string, unknown>)?.family_id).toBe(familyId);
		// The error's name under `cause`, not its message: the message stays in
		// the log.
		expect(storeEvent?.details).toEqual({ family_id: familyId, cause: { name: "Error" } });
	});

	it("keeps what a Redis reply quotes out of introspect.store_unavailable", async () => {
		// A Redis reply error quotes the command it refused, arguments and all;
		// an audit sink is a record other systems read.
		const leaked = "devauth:family:SECRET-TOKEN";
		const token = await makeAccessToken({ family_id: "fam-reply-error" });
		const reply = Object.assign(
			new Error(
				`ERR unknown command 'evalsha', with args beginning with: 'sha' '1' '${leaked}' 'x'`,
			),
			{ name: "ReplyError", command: { name: "evalsha", args: ["sha", "1", leaked] } },
		);
		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockRejectedValue(reply),
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

		expect(res.status).toBe(503);
		const storeEvent = events.find((e) => e.type === "introspect.store_unavailable");
		expect(storeEvent?.details).toEqual({
			family_id: "fam-reply-error",
			cause: { name: "ReplyError" },
		});
		expect(JSON.stringify(events)).not.toContain(leaked);
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
		// family_id: "" is treated as missing
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
// /introspect token_type + access-only enforcement (RFC 7662 §2.2)
//
// `token_type` is `"Bearer"` for an active access token, never the JOSE `typ`
// (e.g. "at+jwt"): RFC 7662 references the OAuth Token Type registry. The
// verifier's `typ` pin answers RT and id_token JWTs `{ active: false }`.
// ---------------------------------------------------------------------------

describe("/introspect — token_type + access-only enforcement", () => {
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

	it("returns active=true with token_type=Bearer + jti for a valid access token (NOT 'at+jwt')", async () => {
		// RFC 6750 §6.1.1 — `Bearer` is the OAuth Token Type; the JOSE `typ`
		// ("at+jwt") is the wrong namespace per RFC 7662 §2.2, which also lists
		// `jti` as a registered response field.
		const token = await makeAccessToken({ client_id: "client1", jti: "jti-sf8-red1" });
		const app = await buildApp();
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(res.body.token_type).toBe("Bearer");
		expect(res.body.token_type).not.toBe("at+jwt");
		expect(res.body.jti).toBe("jti-sf8-red1");
	});

	it("returns active=false for a refresh token (no leak of RT validity)", async () => {
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

	it("returns active=false for an id_token", async () => {
		// Same RFC 7662 §2.1 reasoning as RT: id_tokens are not introspectable
		// access tokens; treating them as active leaks information.
		const token = await makeIdToken();
		const app = await buildApp();
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
	});

	it("response carries client_id (RFC 7662 §2.2 RECOMMENDED), taken from azp when the token has no client_id claim", async () => {
		// A token may carry `azp` (RFC 9068 §2.2) rather than `client_id`, and
		// RFC 7662 §2.2 lists `client_id` as RECOMMENDED in the response, so
		// introspection answers `client_id: payload.client_id ?? azp`: resource
		// servers see the authorized-party identifier under the standard field
		// name either way.
		const token = await makeAccessToken({ azp: "client1" });
		const app = await buildApp();
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(res.body.client_id).toBe("client1");
	});

	it("active access-token response carries RFC 7662 fields without leaking family_id", async () => {
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
// oauthModule — refreshTokenFamilyRevocation composition via createTestApp
//
// oauthModule is booted via the boot planner; refreshTokenFamilyRevocation
// flows through the DI graph into createOAuthRouter's typed deps, and the
// family-revoke cascade must fire.
// ---------------------------------------------------------------------------

describe("oauthModule — refreshTokenFamilyRevocation composition via createTestApp", () => {
	it("threads refreshTokenFamilyRevocation through to /introspect so family revocation returns active:false", async () => {
		const familyId = "fam-module-revoked";
		const token = await makeAccessToken({ family_id: familyId });

		const refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation = {
			revokeFamily: vi.fn(),
			isFamilyRevoked: vi.fn().mockResolvedValue(true),
		};

		// refreshTokenFamilyRevocation flows through the DI graph as a typed slot;
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
				// oauthModule mounts /oauth/revoke, so the boot validator requires a
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
			bootstrapComponents: { config: withOauthCaptures(config), pathResolver: (s) => s },
		});

		const app = express();
		app.set("trust proxy", 1);
		app.use(express.json());
		app.use(express.urlencoded({ extended: false }));
		for (const route of handle.inspect.routes) {
			app.use(route.contribution.mountPath, route.contribution.handler);
		}

		const res = await introspect(app, token);

		// The store was consulted and the family is revoked → inactive.
		expect(res.status).toBe(200);
		expect(res.body.active).toBe(false);
		expect(refreshTokenFamilyRevocation.isFamilyRevoked).toHaveBeenCalledWith(familyId);

		await handle.dispose();
	});
});

/*
 * Introspection describes the TOKEN: a token whose subject has user claims in
 * the Store (e.g. `email_verified`) still introspects to token metadata alone.
 *
 * RFC 7662 §2.2 defines the response as meta-information about the token, and
 * §5: "Omitting privacy-sensitive information from an introspection response
 * is the simplest way of minimizing privacy issues", alongside a `MUST` to
 * prevent disclosure of user identifiers to unintended parties.
 *
 * Neither way to answer differently buys anything `/userinfo` does not already
 * give a resource server holding the token: minting user claims into every
 * access token spreads PII into a credential that transits more places than an
 * id_token and goes stale when the Store changes it (access tokens are not
 * re-derived); reading the session store from the introspect handler turns a
 * session-store outage into an introspection outage, on a hot path resource
 * servers call per request.
 */
describe("/introspect carries token metadata only", () => {
	/**
	 * Exactly what this AS answers with, as a closed list — an RFC 7662 §2.2
	 * **subset plus extensions**, not the §2.2 set:
	 *
	 * - `username` and `nbf` are §2.2 members deliberately omitted (this AS
	 *   issues `at+jwt` without `nbf` and does not persist a human-readable
	 *   username — see `IntrospectResponse`).
	 * - `azp` is not a §2.2 member; it mirrors RFC 9068's authorized-party claim.
	 * - `cnf` is the token-binding confirmation mirror.
	 * - `acr` and `auth_time` are RFC 9470 §6.2's members, and `amr` beside
	 *   them: the authentication event the token carries, not the user's claims.
	 *
	 * §2.2 permits both directions: every member is optional, and
	 * "implementations MAY extend this structure with their own
	 * service-specific response names".
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
		"acr",
		"amr",
		"auth_time",
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

	it("does not carry email_verified or email", async () => {
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

	it("answers the acr, amr and auth_time the token carries (RFC 9470 §6.2)", async () => {
		const token = await makeAccessToken({
			client_id: "client1",
			acr: "urn:example:mfa",
			amr: ["pwd", "otp", "mfa"],
			auth_time: 1_776_729_600,
		});
		const app = await buildApp();
		const res = await introspect(app, token);

		expect(res.status).toBe(200);
		expect(res.body.active).toBe(true);
		expect(res.body.acr).toBe("urn:example:mfa");
		expect(res.body.amr).toEqual(["pwd", "otp", "mfa"]);
		expect(res.body.auth_time).toBe(1_776_729_600);
	});

	it("omits acr, amr and auth_time when the token carries none", async () => {
		const token = await makeAccessToken({ client_id: "client1" });
		const app = await buildApp();
		const res = await introspect(app, token);

		expect(res.body.active).toBe(true);
		expect(res.body).not.toHaveProperty("acr");
		expect(res.body).not.toHaveProperty("amr");
		expect(res.body).not.toHaveProperty("auth_time");
	});

	it("omits an acr, amr or auth_time that is not well-formed", async () => {
		const app = await buildApp();
		for (const bad of [
			{ acr: "", amr: [], auth_time: "1776729600" },
			{ acr: 7, amr: "pwd", auth_time: -1 },
			{ acr: ["urn:example:mfa"], amr: ["pwd", 7], auth_time: 1_776_729_600.5 },
		]) {
			const res = await introspect(app, await makeAccessToken({ client_id: "client1", ...bad }));
			expect(res.body.active, JSON.stringify(bad)).toBe(true);
			expect(res.body, JSON.stringify(bad)).not.toHaveProperty("acr");
			expect(res.body, JSON.stringify(bad)).not.toHaveProperty("amr");
			expect(res.body, JSON.stringify(bad)).not.toHaveProperty("auth_time");
		}
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
