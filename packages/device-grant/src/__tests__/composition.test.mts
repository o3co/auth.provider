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
 * The Quick start's modules, in the order given, plus what supplies their
 * slots. `jwksModule` is there because `oauthModule` activates discovery and
 * a discovery document without `jwks_uri` refuses to boot;
 * `memoryAccessTokenDenylistModule` because `oauthModule` mounts
 * `/oauth/revoke` and the fixture declares the denylist capability.
 */
const bootWith = async (config: AppConfig, ordered: readonly Module[]) => {
	const handle = await createApp({
		modules: [
			...ordered,
			sessionModule,
			memoryDeviceCodeStoreModule,
			memoryRateLimiterModule,
			jwksModule,
			memoryAccessTokenDenylistModule,
			memorySessionStoresModule,
			memoryFederationTokenStoreModule,
			deploymentProviders,
		],
		bootstrapComponents: { config, pathResolver: (s: string) => s },
	});
	const app = express();
	app.use(handle.router);
	return { handle, app };
};

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
			deviceGrantModule,
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
