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

/**
 * End-to-end coverage for the senderConstrained 3-layer propagation path
 * and the shared grant-dispatch enforcement introduced in Wave 2 Phase 1c.
 *
 * Layer 1 (persisted): Client.senderConstrained
 * Layer 2 (projection): PublicClient.senderConstrained (auto via Omit)
 * Layer 3 (grant ctx): AuthenticatedClient.senderConstrained
 *
 * Enforcement runs once per /token request, before the concrete grant
 * handler is invoked, so every registered grant_type inherits the check.
 */

import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantHandler,
	InMemoryClientRepository,
	type SenderConstraint,
	type TokenBinding,
	type TokenBindingMechanism,
	tokenBindingMw,
} from "@o3co/auth-provider-core";
import { GrantRegistry } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createOAuthRouter } from "#/routes.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const ISSUER = "https://auth.example";
const TEST_CLIENT_ID = "sc-client";
const TEST_CLIENT_SECRET = "sc-secret";
const TEST_BASIC_AUTH = `Basic ${Buffer.from(`${TEST_CLIENT_ID}:${TEST_CLIENT_SECRET}`).toString("base64")}`;

const fullConfig = {
	oauth: {
		jwt: { issuer: ISSUER },
		accessToken: { expiresIn: 3600 },
	},
	rateLimit: { failMode: "open" as const },
	endpoints: { login: { url: "/login" } },
} as unknown as AppConfig;

const codeRepoStub: CodeRepository = {
	createCode: async () => ({
		code: "code-x",
		client_id: TEST_CLIENT_ID,
		redirect_uri: "",
	}),
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

// --------------------------------------------------------------------------
// Shared helpers
// --------------------------------------------------------------------------

interface CapturingHandler extends GrantHandler {
	readonly captured: { ctx?: GrantContext; invoked: boolean };
}

const capturingHandler = (): CapturingHandler => {
	const captured: { ctx?: GrantContext; invoked: boolean } = { invoked: false };
	return {
		captured,
		handle: async (ctx) => {
			captured.ctx = ctx;
			captured.invoked = true;
			return {
				result: {
					status: 200,
					tokens: { access_token: "stub", token_type: "Bearer" },
				},
			};
		},
	};
};

interface BuildOptions {
	readonly clientRepo: ClientRepository;
	readonly mountMw?: boolean;
	readonly mechanisms?: readonly TokenBindingMechanism[];
	readonly config?: AppConfig;
	/**
	 * The grant type the handler is registered under. Defaults to
	 * `client_credentials`; the WebAuthn URN case below uses it to show that a
	 * grant contributed by another package inherits this gate unchanged (#489).
	 */
	readonly grantType?: string;
}

async function buildApp(handler: GrantHandler, options: BuildOptions): Promise<express.Express> {
	const app = express();
	app.set("trust proxy", 1);
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));
	const keyStore = createSymmetricKeyStore(SECRET);
	const registry = new GrantRegistry();
	registry.register(options.grantType ?? "client_credentials", handler);
	if (options.mountMw) {
		app.use(
			tokenBindingMw({
				mechanisms: options.mechanisms ?? [],
				dispatchPolicy: "intent-explicit",
			}),
		);
	}
	const { router } = await createOAuthRouter(express, {
		registry,
		config: options.config ?? fullConfig,
		clientRepository: options.clientRepo,
		codeRepository: codeRepoStub,
		keyStore,
	});
	app.use("/oauth", router);
	return app;
}

function makeInMemoryRepo(
	sc?: SenderConstraint,
	allowedGrantTypes: readonly string[] = ["client_credentials"],
): ClientRepository {
	return new InMemoryClientRepository(
		new Map([
			[
				TEST_CLIENT_ID,
				{
					tokenEndpointAuthMethod: "client_secret_basic" as const,
					clientSecret: TEST_CLIENT_SECRET,
					allowedRedirectUris: [],
					allowedScopes: ["read"],
					allowedAudiences: ["https://api.example"],
					allowedGrantTypes: [...allowedGrantTypes],
					...(sc !== undefined && { senderConstrained: sc }),
				},
			],
		]),
	);
}

// --------------------------------------------------------------------------
// Propagation tests (T1.13)
// --------------------------------------------------------------------------

describe("senderConstrained three-layer propagation", () => {
	it("persists on Client, surfaces on PublicClient via findById", async () => {
		const sc: SenderConstraint = { required: true, methods: ["dpop"] };
		const repo = makeInMemoryRepo(sc);
		const client = await repo.findById(TEST_CLIENT_ID);
		expect(client).not.toBeNull();
		expect(client?.senderConstrained).toEqual({ required: true, methods: ["dpop"] });
	});

	it("surfaces on AuthenticatedClient via the /token route projection", async () => {
		const sc: SenderConstraint = { required: false, methods: ["dpop"] };
		const repo = makeInMemoryRepo(sc);
		const handler = capturingHandler();
		const app = await buildApp(handler, { clientRepo: repo });

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(200);
		expect(handler.captured.ctx?.authenticatedClient?.senderConstrained).toEqual({
			required: false,
			methods: ["dpop"],
		});
	});
});

// --------------------------------------------------------------------------
// Type shape test (T1.13 / type assertion)
// --------------------------------------------------------------------------

describe("SenderConstraint type shape", () => {
	it("accepts required:boolean + methods:string[]", () => {
		const sc: SenderConstraint = { required: true, methods: ["dpop", "mtls"] };
		expect(sc.required).toBe(true);
		expect(sc.methods).toEqual(["dpop", "mtls"]);
	});
});

// --------------------------------------------------------------------------
// Enforcement tests (T1.15)
// --------------------------------------------------------------------------

const fakeDPoP: TokenBinding = { kind: "dpop", confirmation: { jkt: "SC-INTEGRATION-JKT" } };

const dpopMechanism: TokenBindingMechanism = {
	kind: "dpop",
	intentExplicit: true,
	extract: async () => fakeDPoP,
};

describe("senderConstrained enforcement (shared grant-dispatch path)", () => {
	it("rejects invalid_client when required and no binding presented", async () => {
		const sc: SenderConstraint = { required: true, methods: ["dpop"] };
		const repo = makeInMemoryRepo(sc);
		const handler = capturingHandler();
		// No tokenBindingMw mounted → ctx.tokenBinding is undefined
		const app = await buildApp(handler, { clientRepo: repo, mountMw: false });

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
		expect(res.body.error_description).toBe("sender-constrained binding required, none provided");
		// Grant handler must NOT have been invoked
		expect(handler.captured.invoked).toBe(false);
	});

	it("rejects unauthorized_client when binding kind not in methods", async () => {
		// Client allows mtls only; DPoP mechanism will produce kind="dpop"
		const sc: SenderConstraint = { required: true, methods: ["mtls"] };
		const repo = makeInMemoryRepo(sc);
		const handler = capturingHandler();
		const app = await buildApp(handler, {
			clientRepo: repo,
			mountMw: true,
			mechanisms: [dpopMechanism],
		});

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("unauthorized_client");
		expect(res.body.error_description).toContain("kind=dpop");
		// Grant handler must NOT have been invoked
		expect(handler.captured.invoked).toBe(false);
	});

	it("allows when binding kind is in methods", async () => {
		const sc: SenderConstraint = { required: true, methods: ["dpop"] };
		const repo = makeInMemoryRepo(sc);
		const handler = capturingHandler();
		const app = await buildApp(handler, {
			clientRepo: repo,
			mountMw: true,
			mechanisms: [dpopMechanism],
		});

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(200);
		// Grant handler MUST have been invoked
		expect(handler.captured.invoked).toBe(true);
	});

	it("emits WWW-Authenticate: Basic on the invalid_client 401 (RFC 7235 §3.1 conformance)", async () => {
		// Sibling invalid_client 401s in clientAuthMw set this header; the
		// new sender-constraint reject must too, for consistency and so
		// RFC-conformant Basic clients see the expected challenge.
		const sc: SenderConstraint = { required: true, methods: ["dpop"] };
		const repo = makeInMemoryRepo(sc);
		const handler = capturingHandler();
		const app = await buildApp(handler, { clientRepo: repo, mountMw: false });

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(401);
		expect(res.headers["www-authenticate"]).toBe(`Basic realm="${ISSUER}"`);
	});

	it("never derives the reject-path realm from the request", async () => {
		// The realm on this path used to interpolate a local whose fallback was
		// `req.get("host")`, so behind a trusted proxy the caller chose the value
		// embedded in the `WWW-Authenticate` quoted-string. `"` is deliberately
		// outside SAFE_REALM_CHARS precisely because it terminates that string.
		// #266 removed the fallback outright: the realm is the configured issuer.
		const sc: SenderConstraint = { required: true, methods: ["dpop"] };
		const repo = makeInMemoryRepo(sc);
		const handler = capturingHandler();
		const app = await buildApp(handler, { clientRepo: repo, mountMw: false });

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.set("Host", 'evil.example" injected="1')
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(401);
		expect(res.headers["www-authenticate"]).toBe(`Basic realm="${ISSUER}"`);
		expect(res.headers["www-authenticate"]).not.toContain("evil.example");
	});

	it("still emits the configured realm for a benign but different Host", async () => {
		const sc: SenderConstraint = { required: true, methods: ["dpop"] };
		const repo = makeInMemoryRepo(sc);
		const handler = capturingHandler();
		const app = await buildApp(handler, { clientRepo: repo, mountMw: false });

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.set("Host", "provider.internal")
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(401);
		expect(res.headers["www-authenticate"]).toBe(`Basic realm="${ISSUER}"`);
		expect(res.headers["www-authenticate"]).not.toContain("provider.internal");
	});

	it("rejects invalid_client when req.tokenBinding is null (defensive against custom middleware)", async () => {
		// The type contract is `req.tokenBinding?: TokenBinding`, so a custom
		// middleware setting `null` would be a type violation. But at the JS
		// layer the enforcement uses `!ctx.tokenBinding` (truthy check) so
		// even a runtime `null` is treated as "no binding" rather than
		// silently bypassing the reject path. This test pins the defensive
		// semantic.
		const sc: SenderConstraint = { required: true, methods: ["dpop"] };
		const repo = makeInMemoryRepo(sc);
		const handler = capturingHandler();
		const app = express();
		app.set("trust proxy", 1);
		app.use(express.json());
		app.use(express.urlencoded({ extended: false }));
		// Middleware that simulates a misbehaving downstream wiring: assigns
		// null instead of omitting the field.
		app.use((req, _res, next) => {
			(req as unknown as { tokenBinding: TokenBinding | null }).tokenBinding = null;
			next();
		});
		const keyStore = createSymmetricKeyStore(SECRET);
		const registry = new GrantRegistry();
		registry.register("client_credentials", handler);
		const { router } = await createOAuthRouter(express, {
			registry,
			config: fullConfig,
			clientRepository: repo,
			codeRepository: codeRepoStub,
			keyStore,
		});
		app.use("/oauth", router);

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
		expect(handler.captured.invoked).toBe(false);
	});

	it("is advisory when required:false (binding kind mismatch does NOT reject)", async () => {
		// Spec §4.8: required:false means methods is purely advisory —
		// the grant succeeds regardless of binding presence or kind. Pins
		// the no-reject path so the JSDoc's "advisory" contract has a
		// regression guard.
		const sc: SenderConstraint = { required: false, methods: ["mtls"] };
		const repo = makeInMemoryRepo(sc);
		const handler = capturingHandler();
		const app = await buildApp(handler, {
			clientRepo: repo,
			mountMw: true,
			mechanisms: [dpopMechanism], // kind=dpop, mismatch with methods=["mtls"]
		});

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(200);
		expect(handler.captured.invoked).toBe(true);
	});

	it("is a no-op when senderConstrained is absent on the client", async () => {
		// No senderConstrained → any request passes regardless of binding state
		const repo = makeInMemoryRepo(undefined);
		const handler = capturingHandler();
		// No binding mw either — still succeeds
		const app = await buildApp(handler, { clientRepo: repo, mountMw: false });

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(200);
		expect(handler.captured.invoked).toBe(true);
	});
});

// --------------------------------------------------------------------------
// The gate is the only sender-constraint rule any grant needs (#489)
// --------------------------------------------------------------------------

describe("senderConstrained enforcement reaches grants contributed by other packages", () => {
	// The WebAuthn grant lives in @o3co/auth-provider-webauthn and is registered
	// through the `contributes.grants` slot, so it never sees this check in its
	// own source. #489 asked what stops a client registered
	// `senderConstrained: "dpop"` from obtaining an unbound access token from it
	// when the request carries no proof; the answer is this gate, which runs
	// before every handler and does not know one grant type from another. The
	// handler adds no second copy of the rule, so the property is pinned here,
	// on the code that actually holds it, with the URN as the vehicle.
	const WEBAUTHN_GRANT_TYPE = "urn:o3co:oauth:grant-type:webauthn";

	it("refuses a proofless request for the WebAuthn grant type, before the handler runs", async () => {
		const sc: SenderConstraint = { required: true, methods: ["dpop"] };
		const repo = makeInMemoryRepo(sc, [WEBAUTHN_GRANT_TYPE]);
		const handler = capturingHandler();
		// No tokenBindingMw mounted → ctx.tokenBinding is undefined.
		const app = await buildApp(handler, {
			clientRepo: repo,
			mountMw: false,
			grantType: WEBAUTHN_GRANT_TYPE,
		});

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: WEBAUTHN_GRANT_TYPE });

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
		expect(res.body.error_description).toBe("sender-constrained binding required, none provided");
		// No assertion is verified, no token is minted: the grant never ran.
		expect(handler.captured.invoked).toBe(false);
	});

	it("admits the WebAuthn grant type once the required binding is presented", async () => {
		const sc: SenderConstraint = { required: true, methods: ["dpop"] };
		const repo = makeInMemoryRepo(sc, [WEBAUTHN_GRANT_TYPE]);
		const handler = capturingHandler();
		const app = await buildApp(handler, {
			clientRepo: repo,
			mountMw: true,
			mechanisms: [dpopMechanism],
			grantType: WEBAUTHN_GRANT_TYPE,
		});

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: WEBAUTHN_GRANT_TYPE });

		expect(res.status).toBe(200);
		expect(handler.captured.invoked).toBe(true);
		// And the confirmation the gate insisted on is the one the handler sees,
		// which is what the grant now puts on its access token.
		expect(handler.captured.ctx?.tokenBinding).toEqual(fakeDPoP);
	});
});
