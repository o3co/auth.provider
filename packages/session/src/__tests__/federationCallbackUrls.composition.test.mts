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
 * Where the federation routes take each federation's callback URL from,
 * booted through core's `createApp` with the session module: the flat
 * `callbackURL` of each enabled `core.federations` entry, as core reads the
 * entries it dispatches. The start hands that URL to the adapter as
 * `redirectUri`, which the provider here echoes into its authorization URL.
 */

import {
	type AppConfig,
	createApp,
	defaultRefreshTokenFamilyRevocationModule,
	defineModule,
	type FederationProvider,
	memoryFederationTokenStoreModule,
	memoryRefreshTokenFamilyStoreModule,
	memorySessionStoresModule,
	sessionLifecycleModule,
	type UserRepository,
} from "@o3co/auth-provider-core";
import {
	federationTypeForTests,
	makeValidAppConfig,
	withInsecureSessionCookie,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { sessionModule } from "#/module.mjs";
import { sessionStoreModule } from "#/modules/sessionStoreModule.mjs";
import { withSessionCaptures } from "./_helpers/sections.mjs";

/** The type the entries name: its schema accepts any key beside core's. */
const TYPE = "loose";

/** A provider named `name` whose authorization URL carries the `redirectUri` the start handed it. */
const echoingProvider = (name: string): FederationProvider => ({
	name,
	scope: ["openid"],
	buildAuthorizationUrl: ({ redirectUri, state }) => {
		const url = new URL(`https://${name}.idp.test/authorize`);
		url.searchParams.set("redirect_uri", redirectUri);
		url.searchParams.set("state", state);
		return url;
	},
	exchangeCode: async () => ({ issuer: `https://${name}.idp.test`, sub: "u", expiresAt: null }),
});

const userRepository: UserRepository = {
	authenticate: async () => null,
	authenticateByToken: async () => null,
};

let disposeLast: (() => Promise<void>) | undefined;

afterEach(async () => {
	await disposeLast?.();
	disposeLast = undefined;
});

/**
 * Boots the session routes over `federations` as `core.federations`, the
 * type `loose` registered, and any `extra` modules; answers the app.
 */
async function boot(federations: Readonly<Record<string, object>>): Promise<express.Express> {
	const base = withInsecureSessionCookie(makeValidAppConfig());
	const config = withSessionCaptures({
		...base,
		core: { ...base.core, federations },
	}) as unknown as AppConfig;
	const handle = await createApp({
		modules: [
			sessionStoreModule,
			sessionModule,
			memorySessionStoresModule,
			sessionLifecycleModule,
			memoryFederationTokenStoreModule,
			memoryRefreshTokenFamilyStoreModule,
			defaultRefreshTokenFamilyRevocationModule,
			federationTypeForTests(TYPE, { provider: (instance) => echoingProvider(instance.name) }),
			defineModule({
				name: "test:deployment-providers",
				provides: { userRepository: () => userRepository },
			}),
		],
		bootstrapComponents: { config, pathResolver: (s: string) => s },
	});
	disposeLast = () => handle.dispose();
	const app = express();
	app.use(handle.router);
	return app;
}

/** The `redirect_uri` the start of `name` handed its adapter. */
async function startRedirectUri(app: express.Express, name: string): Promise<string | null> {
	const start = await request(app).get(`/session/oauth/federation/${name}`);
	expect(start.status).toBe(302);
	return new URL(start.headers.location as string).searchParams.get("redirect_uri");
}

describe("the federation routes take each callback URL from the flat entries core enables", () => {
	it("hands each enabled entry's start its own flat callbackURL", async () => {
		const app = await boot({
			alpha: {
				enabled: true,
				type: TYPE,
				callbackURL: "https://auth.test/session/oauth/federation/alpha/callback",
			},
			beta: {
				enabled: true,
				type: TYPE,
				callbackURL: "https://auth.test/session/oauth/federation/beta/callback",
			},
		});
		expect(await startRedirectUri(app, "alpha")).toBe(
			"https://auth.test/session/oauth/federation/alpha/callback",
		);
		expect(await startRedirectUri(app, "beta")).toBe(
			"https://auth.test/session/oauth/federation/beta/callback",
		);
	});

	it("boots and routes an entry that holds an object under a key named after its type, beside its flat callbackURL", async () => {
		// The key is one of the type's own: its schema accepts it, and the
		// callback URL is still the flat one core requires.
		const app = await boot({
			corp: {
				enabled: true,
				type: TYPE,
				callbackURL: "https://auth.test/session/oauth/federation/corp/callback",
				[TYPE]: { issuer: "https://corp.idp.test", callbackURL: "https://elsewhere.test/cb" },
			},
		});
		expect(await startRedirectUri(app, "corp")).toBe(
			"https://auth.test/session/oauth/federation/corp/callback",
		);
	});

	it("takes nothing from a disabled entry: its type registers no provider, and its start is not found", async () => {
		const app = await boot({
			off: {
				enabled: false,
				type: TYPE,
				callbackURL: "https://auth.test/session/oauth/federation/off/callback",
			},
		});
		const start = await request(app).get("/session/oauth/federation/off");
		expect(start.status).toBe(404);
	});
});
