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
 * The refresh grant holds a policy to the original grant and to the audience
 * it chose: the ceiling is never an array the policy is handed, and an
 * audience the policy chose is never replaced by one a `resource` derives.
 */

import { createSecretKey } from "node:crypto";
import {
	type AuthenticatedClient,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
	type GrantPolicyHook,
} from "@o3co/auth-provider-core";
import {
	createTestOAuthTokenSettings,
	createTestTokenBindingSettings,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import { decodeJwt, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { createRefreshTokenGrant, type RefreshTokenGrantDeps } from "#/grants/refreshToken.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const CLIENT_ID = "client1";
const API = "https://api.example";

const refreshToken = (): Promise<string> =>
	new SignJWT({ sub: "u1", scope: "read" })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
		.setIssuer("localhost")
		.setAudience(CLIENT_ID)
		.setExpirationTime("24h")
		.sign(createSecretKey(Buffer.from(SECRET)));

const grantWith = (evaluate: GrantPolicyHook["evaluate"]) =>
	createRefreshTokenGrant({
		sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		config: {
			oauth: {
				jwt: { secret: SECRET },
				accessToken: { expiresIn: 3600 },
				refreshToken: { expiresIn: 86400, unknownFamilyPolicy: "reject" },
				resourceIndicator: { enabled: true },
			},
		} as unknown as GrantDependencies["config"],
		oauthTokenSettings: createTestOAuthTokenSettings({ resourceIndicatorEnabled: true }),
		tokenBindingSettings: createTestTokenBindingSettings(),
		keyStore,
		grantPolicy: { kind: "stub", evaluate },
	} as RefreshTokenGrantDeps);

const ctx = async (
	body: Record<string, unknown>,
	allowedAudiences: readonly string[] = [API],
): Promise<GrantContext> => ({
	body: { grant_type: "refresh_token", refresh_token: await refreshToken(), ...body },
	session: {},
	issuer: "localhost",
	metadata: {},
	authenticatedClient: {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic",
		allowedGrantTypes: ["refresh_token"],
		allowedScopes: ["read", "admin"],
		allowedAudiences,
	} as AuthenticatedClient,
});

describe("refresh_token — a policy cannot widen the original grant through its input", () => {
	it("refuses a scope the policy wrote into originalScope 500", async () => {
		const { result } = await grantWith(async (request) => {
			(request.originalScope as string[]).push("admin");
			return { outcome: "allow", grantedScope: ["admin"] };
		}).handle(await ctx({}));
		expect(result).toMatchObject({ status: 500, error: "server_error" });
	});
});

describe("refresh_token — an audience the policy chose stands against a resource", () => {
	it.each([
		["the client id listed first", [CLIENT_ID, API]],
		["the client id listed last", [API, CLIENT_ID]],
	] as const)(
		"refuses a resource the chosen client id does not represent (%s)",
		async (_, allowed) => {
			const { result } = await grantWith(async () => ({
				outcome: "allow",
				grantedAudience: [CLIENT_ID],
			})).handle(await ctx({ resource: API }, allowed));
			expect(result).toMatchObject({ status: 400, error: "invalid_target" });
		},
	);

	it("keeps the chosen client id when no resource is requested", async () => {
		const { result } = await grantWith(async () => ({
			outcome: "allow",
			grantedAudience: [CLIENT_ID],
		})).handle(await ctx({}, [API, CLIENT_ID]));
		if (!("tokens" in result)) throw new Error(`expected tokens, got ${JSON.stringify(result)}`);
		expect(decodeJwt(result.tokens.access_token).aud).toBe(CLIENT_ID);
	});

	it("still derives the audience from a resource when the policy chose none", async () => {
		const { result } = await grantWith(async () => ({ outcome: "allow" })).handle(
			await ctx({ resource: API }, [CLIENT_ID, API]),
		);
		if (!("tokens" in result)) throw new Error(`expected tokens, got ${JSON.stringify(result)}`);
		expect(decodeJwt(result.tokens.access_token).aud).toBe(API);
	});
});
