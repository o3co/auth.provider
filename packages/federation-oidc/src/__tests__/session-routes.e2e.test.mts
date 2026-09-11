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

import {
	type AppConfig,
	type AppHandle,
	createApp,
	defaultRefreshTokenFamilyRevocationModule,
	defineModule,
	memoryFederationTokenStoreModule,
	memoryRefreshTokenFamilyStoreModule,
	memorySessionStoresModule,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { sessionModule, sessionStoreModuleFor } from "@o3co/auth-provider-session";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { oidcFederationModule, readOidcFederationConfigs } from "#/module.mjs";
import { createFakeIdp, type FakeIdp } from "./helpers.mjs";

/**
 * #524 acceptance, through the real session routes: two OIDC instances
 * against two issuers in one deployment, each with its own callback; the
 * identity handed to the Store is `<name>:<sub>`; an identity the Store
 * does not know is refused with 401 — no just-in-time provisioning.
 */
const ISSUER_A = "https://idp-a.test";
const ISSUER_B = "https://idp-b.test/realms/b";
const CALLBACK_A = "https://auth.test/session/oauth/federation/idp-a/callback";
const CALLBACK_B = "https://auth.test/session/oauth/federation/idp-b/callback";

function buildConfig(): AppConfig {
	const base = makeValidAppConfig();
	return {
		...base,
		// supertest speaks plain http; a Secure cookie would never come back.
		session: { ...base.session, name: "auth.sid", secure: false },
		federations: {
			"idp-a": {
				enabled: true,
				type: "oidc",
				issuer: ISSUER_A,
				clientId: "client-a",
				clientSecret: "secret-a",
				callbackURL: CALLBACK_A,
				clientUrl: "https://app-a.test/",
			},
			"idp-b": {
				enabled: true,
				type: "oidc",
				clientUrl: "https://app-b.test/",
				oidc: {
					issuer: ISSUER_B,
					clientId: "client-b",
					clientSecret: "secret-b",
					callbackURL: CALLBACK_B,
				},
			},
		},
	} as unknown as AppConfig;
}

async function boot(
	idpA: FakeIdp,
	idpB: FakeIdp,
	authenticateByToken: (token: string) => Promise<unknown>,
) {
	const config = buildConfig();
	const repo = {
		authenticate: vi.fn(async () => null),
		authenticateByToken: vi.fn(authenticateByToken),
	};

	const configsModule = defineModule({
		name: "test:oidc-configs",
		requires: ["config"] as const,
		provides: {
			oidcFederationConfigs: ({ config: c }) => {
				const read = readOidcFederationConfigs((c as AppConfig).federations);
				return {
					"idp-a": { ...read["idp-a"], fetch: idpA.fetch },
					"idp-b": { ...read["idp-b"], fetch: idpB.fetch },
				} as never;
			},
		},
	});
	const repositoryModule = defineModule({
		name: "test:user-repository",
		provides: { userRepository: () => repo } as never,
	});

	const handle = await createApp({
		modules: [
			sessionStoreModuleFor(config),
			sessionModule,
			memorySessionStoresModule,
			memoryFederationTokenStoreModule,
			memoryRefreshTokenFamilyStoreModule,
			defaultRefreshTokenFamilyRevocationModule,
			repositoryModule,
			configsModule,
			oidcFederationModule("idp-a"),
			oidcFederationModule("idp-b"),
		],
		bootstrapComponents: { config, pathResolver: (s: string) => s },
	});
	const app = express();
	app.use(handle.router);
	return { handle, app, repo };
}

/** Start the federation, hand the IdP the transaction's nonce, return what the callback needs. */
async function startLogin(agent: ReturnType<typeof request.agent>, name: string, idp: FakeIdp) {
	const start = await agent.get(`/session/oauth/federation/${name}`);
	expect(start.status).toBe(302);
	const authUrl = new URL(start.headers.location ?? "");
	idp.nonce = authUrl.searchParams.get("nonce") ?? undefined;
	return { authUrl, state: authUrl.searchParams.get("state") ?? "" };
}

let handleRef: AppHandle | undefined;
afterEach(async () => {
	await handleRef?.dispose();
	handleRef = undefined;
});

describe("OIDC federation through the session routes (#524)", () => {
	it("refuses an identity the Store does not know with 401, keyed <name>:<sub>", async () => {
		const idpA = await createFakeIdp({ issuer: ISSUER_A, clientId: "client-a", sub: "sub-a-1" });
		const idpB = await createFakeIdp({ issuer: ISSUER_B, clientId: "client-b", sub: "sub-b-1" });
		const { handle, app, repo } = await boot(idpA, idpB, async () => null);
		handleRef = handle;

		const agent = request.agent(app);
		const { authUrl, state } = await startLogin(agent, "idp-a", idpA);
		expect(`${authUrl.origin}${authUrl.pathname}`).toBe(`${ISSUER_A}/authorize`);
		expect(authUrl.searchParams.get("redirect_uri")).toBe(CALLBACK_A);
		expect(authUrl.searchParams.get("client_id")).toBe("client-a");

		const cb = await agent.get(
			`/session/oauth/federation/idp-a/callback?code=code-1&state=${state}`,
		);
		expect(cb.status).toBe(401);
		expect(cb.body).toMatchObject({ error: "unknown_user" });
		expect(repo.authenticateByToken).toHaveBeenCalledWith("idp-a:sub-a-1");

		// The exchange itself went to idp-a's token endpoint with idp-a's callback.
		const token = idpA.lastTokenRequest();
		expect(token?.body?.get("redirect_uri")).toBe(CALLBACK_A);
		expect(idpB.requestsTo("/token")).toHaveLength(0);
	});

	it("two issuers in one deployment, each with its own callback, and a linked identity logs in", async () => {
		const idpA = await createFakeIdp({ issuer: ISSUER_A, clientId: "client-a", sub: "sub-a-1" });
		const idpB = await createFakeIdp({ issuer: ISSUER_B, clientId: "client-b", sub: "sub-b-1" });
		const { handle, app, repo } = await boot(idpA, idpB, async (token) =>
			token === "idp-b:sub-b-1" ? { id: "user-b", username: "bob" } : null,
		);
		handleRef = handle;

		const agent = request.agent(app);
		const { authUrl, state } = await startLogin(agent, "idp-b", idpB);
		expect(`${authUrl.origin}${authUrl.pathname}`).toBe(`${ISSUER_B}/authorize`);
		expect(authUrl.searchParams.get("redirect_uri")).toBe(CALLBACK_B);
		expect(authUrl.searchParams.get("client_id")).toBe("client-b");

		const cb = await agent.get(
			`/session/oauth/federation/idp-b/callback?code=code-1&state=${state}`,
		);
		expect(cb.status).toBe(302);
		expect(cb.headers.location).toBe("https://app-b.test/");
		expect(repo.authenticateByToken).toHaveBeenCalledWith("idp-b:sub-b-1");
		expect(idpB.lastTokenRequest()?.body?.get("redirect_uri")).toBe(CALLBACK_B);
		expect(idpA.requestsTo("/token")).toHaveLength(0);

		// The same sub under the other issuer is a different identity: not linked, refused.
		const other = request.agent(app);
		const second = await startLogin(other, "idp-a", idpA);
		idpA.idTokenClaims = { sub: "sub-b-1" };
		idpA.userinfoClaims = { sub: "sub-b-1" };
		const refused = await other.get(
			`/session/oauth/federation/idp-a/callback?code=code-2&state=${second.state}`,
		);
		expect(refused.status).toBe(401);
		expect(repo.authenticateByToken).toHaveBeenLastCalledWith("idp-a:sub-b-1");
	});

	it("a callback whose id_token fails validation never reaches the Store", async () => {
		const idpA = await createFakeIdp({ issuer: ISSUER_A, clientId: "client-a" });
		const idpB = await createFakeIdp({ issuer: ISSUER_B, clientId: "client-b" });
		const { handle, app, repo } = await boot(idpA, idpB, async () => ({ id: "u", username: "u" }));
		handleRef = handle;

		const agent = request.agent(app);
		const { state } = await startLogin(agent, "idp-a", idpA);
		idpA.nonce = "not-this-transaction";
		const cb = await agent.get(
			`/session/oauth/federation/idp-a/callback?code=code-1&state=${state}`,
		);
		expect(cb.status).toBe(502);
		expect(cb.body).toMatchObject({ error: "exchange_failed" });
		expect(repo.authenticateByToken).not.toHaveBeenCalled();
	});
});
