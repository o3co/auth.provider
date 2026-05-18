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
 * End-to-end coverage for the `req.tokenBinding` → `ctx.tokenBinding`
 * propagation path on the `/token` route. The middleware unit tests in
 * `packages/core/src/middleware/__tests__/tokenBinding.test.mts` exercise
 * `tokenBindingMw` against a fake `req`/`res` pair and cannot detect a
 * regression in `routes.mts` ctx construction (e.g. a typo that drops the
 * field). This file mounts the real Express + oauth router stack and
 * asserts that a grant handler observes the value written by the
 * middleware.
 */

import {
	type AppConfig,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantHandler,
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
const TEST_CLIENT_ID = "tb-client";
const TEST_CLIENT_SECRET = "tb-secret";
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

const clientRepo: ClientRepository = (() => {
	const baseClient = {
		clientId: TEST_CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic" as const,
		allowedRedirectUris: [],
		allowedScopes: ["read"],
		allowedAudiences: ["https://api.example"],
		allowedGrantTypes: ["client_credentials"],
	};
	return {
		findById: async (id) => (id === TEST_CLIENT_ID ? baseClient : null),
		authenticate: async (id, secret) =>
			id === TEST_CLIENT_ID && secret === TEST_CLIENT_SECRET ? baseClient : null,
	};
})();

interface CapturingHandler extends GrantHandler {
	readonly captured: { ctx?: GrantContext };
}

const capturingHandler = (): CapturingHandler => {
	const captured: { ctx?: GrantContext } = {};
	return {
		captured,
		handle: async (ctx) => {
			captured.ctx = ctx;
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
	readonly mountMw?: boolean;
	readonly mechanisms?: readonly TokenBindingMechanism[];
}

async function buildApp(
	handler: GrantHandler,
	options: BuildOptions = {},
): Promise<express.Express> {
	const app = express();
	app.set("trust proxy", 1);
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));
	const keyStore = createSymmetricKeyStore(SECRET);
	const registry = new GrantRegistry();
	registry.register("client_credentials", handler);
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
		config: fullConfig,
		clientRepository: clientRepo,
		codeRepository: codeRepoStub,
		keyStore,
	});
	app.use("/oauth", router);
	return app;
}

const fakeDPoP: TokenBinding = { kind: "dpop", confirmation: { jkt: "INTEGRATION-JKT" } };

const dpopMechanism: TokenBindingMechanism = {
	kind: "dpop",
	intentExplicit: true,
	extract: async () => fakeDPoP,
};

describe("/oauth/token — req.tokenBinding → ctx.tokenBinding bridge", () => {
	it("copies the middleware-resolved binding into ctx.tokenBinding", async () => {
		// Confirms routes.mts:265 wires `tokenBinding: req.tokenBinding`. A
		// regression in that one-line spread would silently drop the binding
		// and downstream grant handlers would issue Bearer tokens instead of
		// sender-constrained ones — a security regression that the
		// middleware-only unit tests cannot detect.
		const handler = capturingHandler();
		const app = await buildApp(handler, {
			mountMw: true,
			mechanisms: [dpopMechanism],
		});

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(200);
		expect(handler.captured.ctx?.tokenBinding).toEqual(fakeDPoP);
	});

	it("leaves ctx.tokenBinding undefined when tokenBindingMw is not mounted", async () => {
		// Pins the zero-behavior-change guarantee for Phase 1b deployments
		// that have not opted into a binding mechanism yet.
		const handler = capturingHandler();
		const app = await buildApp(handler, { mountMw: false });

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(200);
		expect(handler.captured.ctx?.tokenBinding).toBeUndefined();
	});

	it("leaves ctx.tokenBinding undefined when tokenBindingMw is mounted with no mechanisms", async () => {
		// Pins the no-op path of tokenBindingMw: an empty registry should be
		// indistinguishable from the not-mounted case so consumers can wire
		// the middleware as a unconditional step in their pipeline.
		const handler = capturingHandler();
		const app = await buildApp(handler, { mountMw: true, mechanisms: [] });

		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", TEST_BASIC_AUTH)
			.type("form")
			.send({ grant_type: "client_credentials" });

		expect(res.status).toBe(200);
		expect(handler.captured.ctx?.tokenBinding).toBeUndefined();
	});
});
