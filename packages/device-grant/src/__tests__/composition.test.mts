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
 * The device grant booted beside `oauthModule` through core's `createApp` —
 * the composition the package README's Quick start describes.
 *
 * Every other test in this package calls a contribution function directly or
 * boots the module alone, and each of those passed while the composition an
 * operator actually writes could not boot: what this package contributes is
 * only checked for real once core's discovery builder, oauth's token endpoint
 * and oauth's router under the same `/oauth` prefix have all seen it. So
 * nothing here is stubbed except the repositories a deployment supplies.
 */

import type {
	AppConfig,
	ClientRepository,
	CodeRepository,
	UserRepository,
} from "@o3co/auth-provider-core";
import {
	createApp,
	createSymmetricKeyStore,
	defineModule,
	jwksModule,
	type Module,
	memoryAccessTokenDenylistModule,
	memoryDeviceCodeStoreModule,
	memoryFederationTokenStoreModule,
	memoryRateLimiterModule,
	memorySessionStoresModule,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { oauthModule } from "@o3co/auth-provider-oauth";
import { sessionModule, sessionStoreModuleFor } from "@o3co/auth-provider-session";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { deviceGrantModule } from "#/module.mjs";
import { DEVICE_CODE_GRANT_TYPE } from "#/types.mjs";

/** The fixture's issuer; discovery prefixes every endpoint with it. */
const ISSUER = "https://auth.test";
const CLIENT_ID = "tv-app";

const deviceClient = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "none" as const,
	allowedScopes: ["openid"],
	defaultScopes: ["openid"],
	allowedGrantTypes: [DEVICE_CODE_GRANT_TYPE],
};

const clientRepository: ClientRepository = {
	findById: async (id) => (id === CLIENT_ID ? (deviceClient as never) : null),
	authenticate: async () => null,
};

/** `oauthModule` requires one; nothing here runs the authorization-code flow. */
const codeRepository: CodeRepository = {
	createCode: async () => {
		throw new Error("the authorization-code flow is not exercised here");
	},
	findByCode: async () => null,
	consumeByCode: async () => null,
	removeByCode: async () => {},
};

const USERNAME = "alice";
const PASSWORD = "correct horse battery staple";

const userRepository: UserRepository = {
	authenticate: async (username, password) =>
		username === USERNAME && password === PASSWORD ? ({ id: "user-1" } as never) : null,
	authenticateByToken: async () => null,
};

/** What a deployment supplies itself: the Quick start's "…the modules that provide what these require". */
const deploymentProviders = defineModule({
	name: "test:deployment-providers",
	provides: {
		clientRepository: () => clientRepository,
		codeRepository: () => codeRepository,
		keyStore: () => createSymmetricKeyStore("device-composition-secret.at-least-32-bytes"),
		userRepository: () => userRepository,
	},
});

const makeConfig = (deviceAuthorization: Record<string, unknown>): AppConfig => {
	const base = makeValidAppConfig();
	return {
		...base,
		// supertest speaks plain HTTP, and express-session sets no `Secure`
		// cookie on it — which also rules out the fixture's `__Host-` name.
		session: { ...base.session, name: "auth.session", secure: false },
		oauth: { ...base.oauth, deviceAuthorization },
	};
};

const ENABLED = {
	enabled: true,
	"verification-uri": `${ISSUER}/device`,
};

/**
 * The Quick start's module list: `ordered` is its first three, whose order a
 * case chooses; then the rest as written; then its "…the modules that
 * provide what these require" — the session and federation-token stores,
 * the access-token denylist the fixture's `oauth.revocation.accessToken`
 * declares, and the repositories and key store.
 */
const bootWith = async (config: AppConfig, ordered: readonly Module[]) => {
	const handle = await createApp({
		modules: [
			...ordered,
			jwksModule,
			sessionModule,
			memoryDeviceCodeStoreModule,
			memoryRateLimiterModule,
			memorySessionStoresModule,
			memoryFederationTokenStoreModule,
			memoryAccessTokenDenylistModule,
			deploymentProviders,
		],
		bootstrapComponents: { config, pathResolver: (s: string) => s },
	});
	const app = express();
	app.use(handle.router);
	return { handle, app };
};

type Agent = ReturnType<typeof request.agent>;

/** The session's double-submit token, fresh: `GET /session/csrf` sets the cookie and returns the value. */
const csrfToken = async (agent: Agent): Promise<{ header: string; token: string }> => {
	const res = await agent.get("/session/csrf");
	expect(res.status).toBe(200);
	return { header: res.body.header_name as string, token: res.body.csrf_token as string };
};

/** Sign in through `POST /session/login`, as the verification page's user would have. */
const signIn = async (agent: Agent): Promise<void> => {
	const { header, token } = await csrfToken(agent);
	const res = await agent
		.post("/session/login")
		.set(header, token)
		.send({ username: USERNAME, password: PASSWORD });
	expect(res.status).toBe(200);
};

/** A device starts the flow; returns the code a person would type. */
const startDevice = async (app: express.Express): Promise<string> => {
	const res = await request(app)
		.post("/oauth/device_authorization")
		.type("form")
		.send({ client_id: CLIENT_ID });
	expect(res.status).toBe(200);
	return res.body.user_code as string;
};

/**
 * Both orders of the two modules that share `/oauth`. `oauthModule`'s router
 * parses JSON and form bodies — Express's defaults, 100 KiB — for every
 * request beneath the prefix, so whatever this package enforces about a body
 * has to hold when that router has already read it.
 */
const orders = [
	[
		"oauthModule listed first",
		(config: AppConfig) => [oauthModule({ config }), deviceGrantModule({ config })],
	],
	[
		"deviceGrantModule listed first",
		(config: AppConfig) => [deviceGrantModule({ config }), oauthModule({ config })],
	],
] as const;

describe("deviceGrantModule beside oauthModule — discovery (RFC 8628 §4)", () => {
	it("boots enabled and advertises device_authorization_endpoint under the issuer", async () => {
		// `oauthModule` always activates discovery, and core's builder refuses
		// an issuer-relative endpoint handed over as a literal `metadata`
		// field. So the one composition that needs this field — an enabled
		// grant beside the token endpoint it is polled at — is the one that
		// has to boot for the field to exist at all.
		const config = makeConfig(ENABLED);
		const { handle, app } = await bootWith(config, [
			sessionStoreModuleFor(config),
			deviceGrantModule({ config }),
			oauthModule({ config }),
		]);
		try {
			const res = await request(app).get("/.well-known/openid-configuration");

			expect(res.status).toBe(200);
			expect(res.body.device_authorization_endpoint).toBe(`${ISSUER}/oauth/device_authorization`);
			// The grant reaches `grant_types_supported` the way every grant
			// does: from the resolver `/oauth/token` dispatches against.
			expect(res.body.grant_types_supported).toContain(DEVICE_CODE_GRANT_TYPE);
		} finally {
			await handle.dispose();
		}
	});
});

describe("deviceGrantModule beside oauthModule — installed but disabled", () => {
	it("does not advertise the grant, and /oauth/token refuses it as unsupported", async () => {
		// `grant_types_supported` is read off the resolver `/oauth/token`
		// dispatches against (#283), so a grant that is contributed is a grant
		// that is advertised — including a handler whose only job is to
		// refuse. The document must say what the endpoint does.
		const config = makeConfig({ enabled: false });
		const { handle, app } = await bootWith(config, [
			sessionStoreModuleFor(config),
			deviceGrantModule({ config }),
			oauthModule({ config }),
		]);
		try {
			const discovery = await request(app).get("/.well-known/openid-configuration");
			expect(discovery.status).toBe(200);
			expect(discovery.body.grant_types_supported).not.toContain(DEVICE_CODE_GRANT_TYPE);
			expect(discovery.body.device_authorization_endpoint).toBeUndefined();

			const token = await request(app)
				.post("/oauth/token")
				.type("form")
				.send({ grant_type: DEVICE_CODE_GRANT_TYPE, client_id: CLIENT_ID, device_code: "x" });
			expect(token.status).toBe(400);
			expect(token.body.error).toBe("unsupported_grant_type");
		} finally {
			await handle.dispose();
		}
	});
});

describe("deviceGrantModule beside oauthModule — POST /oauth/device/verification is JSON-only", () => {
	// A form body is a CORS "simple" request: a browser sends it cross-site,
	// with the victim's session cookie and no preflight. `oauthModule`'s router
	// parses form bodies for every request under `/oauth`, so a rule that
	// rested on this package mounting no form parser held only when this
	// package was listed first. The CSRF token is valid here on purpose: the
	// media type is the first defence, and it must not depend on the second.
	it.each(orders)(
		"refuses a form-encoded approval carrying a valid CSRF token (%s)",
		async (_label, ordered) => {
			const config = makeConfig(ENABLED);
			const { handle, app } = await bootWith(config, [
				sessionStoreModuleFor(config),
				...ordered(config),
			]);
			try {
				const userCode = await startDevice(app);
				const agent = request.agent(app);
				await signIn(agent);
				const { header, token } = await csrfToken(agent);

				const form = await agent
					.post("/oauth/device/verification")
					.set(header, token)
					.type("form")
					.send(`action=approve&user_code=${userCode}`);

				expect(form.status).toBe(415);
				expect(form.body.error).toBe("invalid_request");

				// The same approval as JSON goes through — so what refused the
				// form was its media type, not the session or the token — and it
				// is an approval, not `409 already_decided`: the form decided
				// nothing.
				const json = await agent
					.post("/oauth/device/verification")
					.set(header, token)
					.send({ action: "approve", user_code: userCode });
				expect(json.status).toBe(200);
				expect(json.body.status).toBe("approved");
			} finally {
				await handle.dispose();
			}
		},
	);
});

describe("deviceGrantModule beside oauthModule — the 16 KiB body limit", () => {
	// Both routes parse with a 16 KiB limit, but `body-parser` does not parse a
	// body twice: listed after `oauthModule`, they received whatever its
	// 100 KiB parsers had already read. The bound has to hold in either order,
	// with one answer.
	const TOO_LARGE = { error: "invalid_request", error_description: "body_too_large" };

	it.each(orders)(
		"refuses a 40 KB JSON body at both routes with 413 body_too_large (%s)",
		async (_label, ordered) => {
			const config = makeConfig(ENABLED);
			const { handle, app } = await bootWith(config, [
				sessionStoreModuleFor(config),
				...ordered(config),
			]);
			try {
				const userCode = await startDevice(app);
				const agent = request.agent(app);
				await signIn(agent);
				const { header, token } = await csrfToken(agent);
				const padding = "x".repeat(40_000);

				// Signed in and carrying a valid token, so nothing but the size
				// stands between this lookup and the handler.
				const verification = await agent
					.post("/oauth/device/verification")
					.set(header, token)
					.send({ action: "lookup", user_code: userCode, padding });
				expect(verification.status).toBe(413);
				expect(verification.body).toEqual(TOO_LARGE);

				const authorization = await request(app)
					.post("/oauth/device_authorization")
					.send({ client_id: CLIENT_ID, padding });
				expect(authorization.status).toBe(413);
				expect(authorization.body).toEqual(TOO_LARGE);
			} finally {
				await handle.dispose();
			}
		},
	);

	it.each(orders)(
		"accepts a body of exactly 16 KiB, as the parsers it stands in for do (%s)",
		async (_label, ordered) => {
			// `express.json({ limit: "16kb" })` accepts exactly 16384 bytes. A
			// restated bound that disagreed with the parser would accept or
			// refuse the same request depending on the module order.
			const config = makeConfig(ENABLED);
			const { handle, app } = await bootWith(config, [
				sessionStoreModuleFor(config),
				...ordered(config),
			]);
			try {
				const body = { client_id: CLIENT_ID, padding: "" };
				body.padding = "x".repeat(16_384 - Buffer.byteLength(JSON.stringify(body)));
				expect(Buffer.byteLength(JSON.stringify(body))).toBe(16_384);

				const res = await request(app).post("/oauth/device_authorization").send(body);
				expect(res.status).toBe(200);
				expect(typeof res.body.device_code).toBe("string");
			} finally {
				await handle.dispose();
			}
		},
	);
});
