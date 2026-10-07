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
 * The presented refresh token's `aud` is the ceiling and the default for the
 * audience of the tokens a refresh issues, as its scope is for their scope:
 * a plain refresh keeps it, a `resource` or a policy audience outside it is
 * refused, and the policy is handed it as `originalAudience`.
 */

import { createSecretKey } from "node:crypto";
import {
	type AuthenticatedClient,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantPolicyHook,
	type GrantPolicyRequest,
	type GrantResult,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	createTestOAuthTokenSettings,
	createTestTokenBindingSettings,
	resolverForTests,
} from "@o3co/auth-provider-core/testing";
import { decodeJwt, SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createRefreshTokenGrant, type RefreshTokenGrantDeps } from "#/grants/refreshToken.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { openedLifecycleStore } from "./_helpers/sessionLifecycle.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const CLIENT_ID = "client1";
const API = "https://api.example";
const OTHER = "https://other.example";

/** A refresh token issued to `CLIENT_ID` (`azp`) for `aud`, or for none. */
const refreshToken = (aud: string | string[] | undefined): Promise<string> => {
	const jwt = new SignJWT({ sub: "u1", scope: "read", azp: CLIENT_ID })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
		.setIssuer("localhost")
		.setExpirationTime("24h");
	if (aud !== undefined) jwt.setAudience(aud);
	return jwt.sign(createSecretKey(Buffer.from(SECRET)));
};

const grantWith = (evaluate?: GrantPolicyHook["evaluate"]) =>
	createRefreshTokenGrant({
		sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		oauthTokenSettings: createTestOAuthTokenSettings({ resourceIndicatorEnabled: true }),
		tokenBindingSettings: createTestTokenBindingSettings(),
		keyStore,
		...(evaluate ? { grantPolicy: { kind: "stub", evaluate } } : {}),
	} as RefreshTokenGrantDeps);

const ctx = (
	token: string,
	body: Record<string, unknown> = {},
	allowedAudiences: readonly string[] = [API, OTHER],
): GrantContext => ({
	body: { grant_type: "refresh_token", refresh_token: token, ...body },
	session: {},
	issuer: "localhost",
	metadata: {},
	authenticatedClient: {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic",
		allowedGrantTypes: ["refresh_token"],
		allowedScopes: ["read"],
		allowedAudiences,
	} as AuthenticatedClient,
});

const issued = (result: GrantResult) => {
	if (!("tokens" in result)) throw new Error(`expected tokens, got ${JSON.stringify(result)}`);
	const refresh = result.tokens.refresh_token;
	if (typeof refresh !== "string") throw new Error("expected a refresh token");
	return {
		access: decodeJwt(result.tokens.access_token),
		refresh,
		refreshClaims: decodeJwt(refresh),
	};
};

describe("refresh_token — a plain refresh keeps the original audience", () => {
	it("keeps a resource aud on the access token and the rotated refresh token", async () => {
		const { result } = await grantWith().handle(ctx(await refreshToken(API)));
		const { access, refreshClaims } = issued(result);
		expect(access.aud).toBe(API);
		expect(refreshClaims.aud).toBe(API);
	});

	it("keeps it across a second refresh with the rotated token", async () => {
		const grant = grantWith();
		const first = issued((await grant.handle(ctx(await refreshToken(API)))).result);
		const second = issued((await grant.handle(ctx(first.refresh))).result);
		expect(second.access.aud).toBe(API);
		expect(second.refreshClaims.aud).toBe(API);
	});

	it("keeps it when a silent policy is wired", async () => {
		const { result } = await grantWith(async () => ({ outcome: "allow" })).handle(
			ctx(await refreshToken(API)),
		);
		expect(issued(result).access.aud).toBe(API);
	});

	it("issues for the client id when the presented token names no aud", async () => {
		const { result } = await grantWith().handle(ctx(await refreshToken(undefined)));
		expect(issued(result).access.aud).toBe(CLIENT_ID);
	});
});

describe("refresh_token — a resource is held to the original audience", () => {
	it("refuses invalid_target for a registered resource outside the original aud", async () => {
		const { result } = await grantWith().handle(ctx(await refreshToken(API), { resource: OTHER }));
		expect(result).toMatchObject({ status: 400, error: "invalid_target" });
	});

	it("refuses invalid_target for a resource outside the client id a token without aud is held to", async () => {
		const { result } = await grantWith().handle(
			ctx(await refreshToken(undefined), { resource: API }),
		);
		expect(result).toMatchObject({ status: 400, error: "invalid_target" });
	});

	it("derives a resource within the original aud", async () => {
		const { result } = await grantWith().handle(
			ctx(await refreshToken([API, OTHER]), { resource: OTHER }),
		);
		const { access, refreshClaims } = issued(result);
		expect(access.aud).toBe(OTHER);
		expect(refreshClaims.aud).toBe(OTHER);
	});
});

describe("refresh_token — a policy audience is held to the original audience", () => {
	it("refuses a registered audience outside the original aud 500", async () => {
		const { result } = await grantWith(async () => ({
			outcome: "allow",
			grantedAudience: [OTHER],
		})).handle(ctx(await refreshToken(API)));
		expect(result).toMatchObject({ status: 500, error: "server_error" });
	});

	it("issues an audience the policy narrows to within the original aud", async () => {
		const { result } = await grantWith(async () => ({
			outcome: "allow",
			grantedAudience: [OTHER],
		})).handle(ctx(await refreshToken([API, OTHER])));
		const { access, refreshClaims } = issued(result);
		expect(access.aud).toBe(OTHER);
		expect(refreshClaims.aud).toBe(OTHER);
	});

	it("hands the policy the original audience", async () => {
		const seen: GrantPolicyRequest[] = [];
		await grantWith(async (request) => {
			seen.push(request);
			return { outcome: "allow" };
		}).handle(ctx(await refreshToken([API, OTHER])));
		expect(seen).toHaveLength(1);
		expect(seen[0]?.originalAudience).toEqual([API, OTHER]);
	});

	it("hands the policy the client id for a token without aud", async () => {
		const seen: GrantPolicyRequest[] = [];
		await grantWith(async (request) => {
			seen.push(request);
			return { outcome: "allow" };
		}).handle(ctx(await refreshToken(undefined)));
		expect(seen[0]?.originalAudience).toEqual([CLIENT_ID]);
	});

	it("refuses an audience the policy wrote into originalAudience 500", async () => {
		const { result } = await grantWith(async (request) => {
			(request.originalAudience as string[]).push(OTHER);
			return { outcome: "allow", grantedAudience: [OTHER] };
		}).handle(ctx(await refreshToken(API)));
		expect(result).toMatchObject({ status: 500, error: "server_error" });
	});
});

/** A token of family `fam-1` and session `sid-1`, as the stores below hold them. */
const familyToken = (aud: string | string[]): Promise<string> =>
	new SignJWT({ sub: "u1", scope: "read", azp: CLIENT_ID, family_id: "fam-1", sid: "sid-1" })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
		.setIssuer("localhost")
		.setAudience(aud)
		.setJti("rt-1")
		.setExpirationTime("24h")
		.sign(createSecretKey(Buffer.from(SECRET)));

/**
 * The grant over spies: `admit`, the session read admission makes for the
 * token's `sid`; `rotate` and `revokeFamily`, the family store's.
 */
const withSpies = (evaluate?: GrantPolicyHook["evaluate"]) => {
	const admit = vi.fn(
		async (): Promise<UserSession | null> => ({
			sid: "sid-1",
			sub: "u1",
			authTime: new Date(),
			createdAt: new Date(),
			expiresAt: new Date(Date.now() + 3600_000),
			claims: {},
			amr: undefined,
			authentication: undefined,
		}),
	);
	const userSessionStore: UserSessionStore = {
		kind: "stub",
		get: admit,
		async create() {},
		async delete() {},
	};
	const rotate = vi.fn(async () => ({ outcome: "rotated" as const }));
	const revokeFamily = vi.fn(async () => {});
	const grant = createRefreshTokenGrant({
		sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		oauthTokenSettings: createTestOAuthTokenSettings({ resourceIndicatorEnabled: true }),
		tokenBindingSettings: createTestTokenBindingSettings(),
		keyStore,
		userSessionStore,
		sessionLifecycleStore: openedLifecycleStore(["sid-1", "u1"]),
		refreshTokenFamilyRotation: { register: vi.fn(async () => {}), rotate },
		refreshTokenFamilyRevocation: { revokeFamily, isFamilyRevoked: async () => false },
		...(evaluate ? { grantPolicy: { kind: "stub", evaluate } } : {}),
	} as RefreshTokenGrantDeps);
	return { grant, admit, rotate, revokeFamily };
};

describe("refresh_token — a plain refresh needs its original audience still registered", () => {
	it("refuses invalid_grant before admission, leaving the family untouched, when the original aud is no longer registered", async () => {
		const { grant, admit, rotate, revokeFamily } = withSpies();
		const { result } = await grant.handle(ctx(await familyToken(API), {}, [OTHER]));
		expect(result).toMatchObject({
			status: 400,
			error: "invalid_grant",
			errorDescription: "the grant's audience is no longer registered for this client",
		});
		expect(admit).not.toHaveBeenCalled();
		expect(rotate).not.toHaveBeenCalled();
		expect(revokeFamily).not.toHaveBeenCalled();
	});

	it("refuses it with a silent policy wired too", async () => {
		const { grant, admit, rotate } = withSpies(async () => ({ outcome: "allow" }));
		const { result } = await grant.handle(ctx(await familyToken(API), {}, []));
		expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
		expect(admit).not.toHaveBeenCalled();
		expect(rotate).not.toHaveBeenCalled();
	});

	it("admits, rotates and issues while the original aud is registered", async () => {
		const { grant, admit, rotate } = withSpies();
		const { result } = await grant.handle(ctx(await familyToken(API), {}, [API]));
		expect(issued(result).access.aud).toBe(API);
		expect(admit).toHaveBeenCalled();
		expect(rotate).toHaveBeenCalledTimes(1);
	});

	it.each([
		["no allowedAudiences", []],
		["other allowedAudiences", [API, OTHER]],
	] as const)("always issues a token for the client id itself (%s)", async (_, allowed) => {
		const { grant, rotate } = withSpies();
		const { result } = await grant.handle(ctx(await familyToken(CLIENT_ID), {}, allowed));
		expect(issued(result).access.aud).toBe(CLIENT_ID);
		expect(rotate).toHaveBeenCalledTimes(1);
	});
});

describe("refresh_token — a resource the registration no longer holds is invalid_target", () => {
	it.each([
		["no policy", undefined],
		["a silent policy", async () => ({ outcome: "allow" as const })],
	] as const)(
		"refuses a resource inside the original aud but outside the registration (%s)",
		async (_, evaluate) => {
			const { grant, admit, rotate, revokeFamily } = withSpies(evaluate);
			const { result } = await grant.handle(
				ctx(await familyToken([API, OTHER]), { resource: API }, [OTHER]),
			);
			expect(result).toMatchObject({ status: 400, error: "invalid_target" });
			expect(admit).not.toHaveBeenCalled();
			expect(rotate).not.toHaveBeenCalled();
			expect(revokeFamily).not.toHaveBeenCalled();
		},
	);

	it("still issues for the registered entry of the same token", async () => {
		const { grant } = withSpies();
		const { result } = await grant.handle(
			ctx(await familyToken([API, OTHER]), { resource: OTHER }, [OTHER]),
		);
		expect(issued(result).access.aud).toBe(OTHER);
	});
});

describe("refresh_token — how the original audience is read", () => {
	it("holds an empty aud array to the client id", async () => {
		const plain = await grantWith().handle(ctx(await refreshToken([])));
		expect(issued(plain.result).access.aud).toBe(CLIENT_ID);
		const targeted = await grantWith().handle(ctx(await refreshToken([]), { resource: API }));
		expect(targeted.result).toMatchObject({ status: 400, error: "invalid_target" });
	});

	it("reads duplicate entries as one audience", async () => {
		const plain = await grantWith().handle(ctx(await refreshToken([API, API])));
		expect(issued(plain.result).access.aud).toBe(API);
		const targeted = await grantWith().handle(
			ctx(await refreshToken([API, API]), { resource: API }),
		);
		expect(issued(targeted.result).access.aud).toBe(API);
		const other = await grantWith().handle(
			ctx(await refreshToken([API, API]), { resource: OTHER }),
		);
		expect(other.result).toMatchObject({ status: 400, error: "invalid_target" });
	});

	it("compares audiences exactly, case included", async () => {
		const upper = "https://API.example";
		const resource = await grantWith().handle(ctx(await refreshToken(API), { resource: upper }));
		expect(resource.result).toMatchObject({ status: 400, error: "invalid_target" });
		const plain = await grantWith().handle(ctx(await refreshToken(upper)));
		expect(plain.result).toMatchObject({ status: 400, error: "invalid_grant" });
		const policy = await grantWith(async () => ({
			outcome: "allow",
			grantedAudience: [upper],
		})).handle(ctx(await refreshToken(API), {}, [API, upper]));
		expect(policy.result).toMatchObject({ status: 500, error: "server_error" });
	});

	it("keeps the first entry of a multi-audience token across two rotations", async () => {
		const grant = grantWith();
		const first = issued((await grant.handle(ctx(await refreshToken([OTHER, API])))).result);
		expect(first.access.aud).toBe(OTHER);
		expect(first.refreshClaims.aud).toBe(OTHER);
		const second = issued((await grant.handle(ctx(first.refresh))).result);
		expect(second.access.aud).toBe(OTHER);
		expect(second.refreshClaims.aud).toBe(OTHER);
	});
});
