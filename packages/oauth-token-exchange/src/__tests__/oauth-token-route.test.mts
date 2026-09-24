/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * A token exchange over HTTP, the way a client makes one: `tokenExchangeModule`
 * composed with `@o3co/auth-provider-oauth`'s `oauthModule` through core's
 * `createApp`, and the request POSTed to the real `/oauth/token` route.
 *
 * The other suites call the handler — directly, or as `grantHandlerResolver`
 * hands it out — so what only the route does is checked here: client
 * authentication, dispatch through the resolver and the explicit grant
 * allowlist the handler declares, and the response the route writes from the
 * handler's result (status, body, `Cache-Control`, the RFC 6749 §5.2 character
 * set of `error_description`). Nothing is stubbed but what a deployment
 * supplies itself: the client and code repositories and the key store.
 */

import {
	type AppConfig,
	type AppHandle,
	type ClientRepository,
	type CodeRepository,
	createApp,
	defaultRefreshTokenFamilyRevocationModule,
	defineModule,
	jwksModule,
	memoryRefreshTokenFamilyStoreModule,
	type PublicClient,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { oauthModule } from "@o3co/auth-provider-oauth";
import express from "express";
import { decodeJwt } from "jose";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "#/grant.mjs";
import { tokenExchangeModule } from "#/module.mjs";
import { ISSUER, keyStore, signSelfIssuedAccessToken } from "./fixtures.mjs";

const SECRET = "gateway-secret";

/** A confidential client registered for the exchange, as the README's Client configuration shows. */
const gateway: PublicClient = {
	clientId: "client-a",
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedRedirectUris: [],
	allowedScopes: ["read", "write"],
	allowedAudiences: ["billing"],
	allowedGrantTypes: [TOKEN_EXCHANGE_GRANT_TYPE],
	backchannelLogoutSessionRequired: true,
	frontchannelLogoutSessionRequired: true,
	allowedAzpForFederationToken: false,
};

/** The same kind of client, registered for other grants only. */
const otherGrants: PublicClient = {
	...gateway,
	clientId: "client-b",
	allowedGrantTypes: ["client_credentials"],
};

/** The same kind of client, registered with no `allowedGrantTypes` at all. */
const { allowedGrantTypes: _omitted, ...noGrants } = { ...gateway, clientId: "client-c" };

const clients = new Map<string, PublicClient>(
	[gateway, otherGrants, noGrants].map((client) => [client.clientId, client]),
);

const clientRepository: ClientRepository = {
	findById: async (id) => clients.get(id) ?? null,
	authenticate: async (id, secret) => (secret === SECRET ? (clients.get(id) ?? null) : null),
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

const deploymentProviders = defineModule({
	name: "test:deployment-providers",
	provides: {
		clientRepository: () => clientRepository,
		codeRepository: () => codeRepository,
		keyStore: () => keyStore,
	},
});

function makeConfig(): AppConfig {
	const base = makeValidAppConfig();
	return {
		...base,
		oauth: {
			...base.oauth,
			jwt: { ...base.oauth.jwt, issuer: ISSUER },
			// This composition wires neither the access-token denylist nor the
			// subject watermark, and says so (the boot refuses an undeclared
			// absence).
			revocation: { accessToken: "unsupported", subject: "unsupported" },
		},
	};
}

describe("token exchange through oauthModule's POST /oauth/token", () => {
	let handle: AppHandle | undefined;
	afterEach(async () => {
		await handle?.dispose();
		handle = undefined;
	});

	/** The README's "Register the grant" composition, booted for real. */
	async function boot(): Promise<express.Express> {
		const config = makeConfig();
		handle = await createApp({
			modules: [
				oauthModule({ config }),
				tokenExchangeModule,
				memoryRefreshTokenFamilyStoreModule,
				defaultRefreshTokenFamilyRevocationModule,
				// The exchange requires an issuer, and with one configured the
				// discovery document needs the `jwks_uri` this module contributes.
				jwksModule,
				deploymentProviders,
			],
			bootstrapComponents: { config, pathResolver: (s: string) => s },
		});
		const app = express();
		app.use(handle.router);
		return app;
	}

	const exchange = (app: express.Express, clientId: string, form: Record<string, string>) =>
		request(app)
			.post("/oauth/token")
			.auth(clientId, SECRET)
			.type("form")
			.send({
				grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
				...form,
			});

	it("issues a narrower access token for the requested audience", async () => {
		const app = await boot();
		const subjectToken = await signSelfIssuedAccessToken({ scope: "read write", aud: "billing" });

		const res = await exchange(app, gateway.clientId, {
			subject_token: subjectToken,
			subject_token_type: ACCESS_TOKEN_TYPE,
			audience: "billing",
			scope: "read",
		});

		expect(res.status).toBe(200);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toMatchObject({
			issued_token_type: ACCESS_TOKEN_TYPE,
			token_type: "Bearer",
			scope: "read",
		});
		expect(res.body.expires_in).toBeGreaterThan(0);
		const issued = decodeJwt(res.body.access_token as string);
		expect(issued).toMatchObject({ iss: ISSUER, sub: "user-1", aud: "billing", scope: "read" });
	});

	// Note 15: the grant denies by absence. Dispatch refuses a registration
	// naming other grants only with the base check's description, which quotes
	// the grant type, and one with no `allowedGrantTypes` with the strict
	// check's, which does not.
	it.each([
		["names other grants only", otherGrants, `grant_type '${TOKEN_EXCHANGE_GRANT_TYPE}'`],
		["omits allowedGrantTypes", noGrants, TOKEN_EXCHANGE_GRANT_TYPE],
	])("refuses a client whose registration %s", async (_case, client, named) => {
		const app = await boot();
		const subjectToken = await signSelfIssuedAccessToken({});

		const res = await exchange(app, client.clientId, {
			subject_token: subjectToken,
			subject_token_type: ACCESS_TOKEN_TYPE,
		});

		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "unauthorized_client",
			error_description: `client is not authorized for ${named}`,
		});
	});

	it("answers a refusal that quotes the request with error_description held to RFC 6749 §5.2", async () => {
		const app = await boot();
		const subjectToken = await signSelfIssuedAccessToken({});

		// `"` is outside §5.2's character set; the handler quotes the value it
		// refuses, and the route replaces what the set does not allow.
		const res = await exchange(app, gateway.clientId, {
			subject_token: subjectToken,
			subject_token_type: 'urn:example:"quoted"',
		});

		expect(res.status).toBe(400);
		expect(res.body).toEqual({
			error: "invalid_request",
			error_description: "subject_token_type 'urn:example:?quoted?' is not supported",
		});
	});

	it("refuses a failed client authentication before the grant runs", async () => {
		const app = await boot();
		const subjectToken = await signSelfIssuedAccessToken({});

		const res = await request(app)
			.post("/oauth/token")
			.auth(gateway.clientId, "wrong-secret")
			.type("form")
			.send({
				grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
				subject_token: subjectToken,
				subject_token_type: ACCESS_TOKEN_TYPE,
			});

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("invalid_client");
	});
});
