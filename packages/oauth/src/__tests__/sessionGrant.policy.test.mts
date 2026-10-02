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
 * The session grant consults a wired `grantPolicy` after admission and its
 * own scope checks, before minting, with core's fail-closed rules: deny is
 * 400 with the policy's error, a throw is 503, a scope or audience past the
 * ceiling is 500.
 */

import {
	type AuthenticatedClient,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
	type GrantPolicyHook,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import { decodeJwt } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createSessionGrant } from "#/grants/session.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";

const config = {
	oauth: {
		jwt: { issuer: "https://issuer.test" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
	},
} as unknown as GrantDependencies["config"];

const CLIENT: AuthenticatedClient = {
	clientId: "app",
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedScopes: ["read", "write"],
	allowedAudiences: ["https://rs-a", "https://rs-b"],
};

const grantWith = (evaluate: GrantPolicyHook["evaluate"]) =>
	createSessionGrant({
		sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		config,
		keyStore: createSymmetricKeyStore("session-policy-test-secret-32-bytes"),
		grantPolicy: { kind: "stub", evaluate },
	});

const ctx = (
	body: Record<string, unknown> = { scope: "read write" },
	overrides: Partial<GrantContext> = {},
): GrantContext => ({
	body,
	session: { isAuthenticated: true, user: { id: "user-1" } },
	issuer: "https://issuer.test",
	metadata: {},
	ip: "203.0.113.7",
	userAgent: "test-agent",
	authenticatedClient: CLIENT,
	...overrides,
});

const minted = (result: Awaited<ReturnType<ReturnType<typeof grantWith>["handle"]>>["result"]) => {
	if (!("tokens" in result)) throw new Error(`expected tokens, got ${JSON.stringify(result)}`);
	return decodeJwt(result.tokens.access_token);
};

describe("session grant — grantPolicy refusals", () => {
	it("answers a deny whose code the token endpoint does not define 400 invalid_request", async () => {
		const { result } = await grantWith(async () => ({
			outcome: "deny",
			error: "access_denied",
			errorDescription: "browser tokens are closed",
		})).handle(ctx());
		expect(result).toEqual({
			status: 400,
			error: "invalid_request",
			errorDescription: "browser tokens are closed",
		});
	});

	it("answers a policy that throws 503", async () => {
		const { result } = await grantWith(async () => {
			throw new Error("decision service down");
		}).handle(ctx());
		expect(result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
		if (!("error" in result)) expect.fail("expected a refusal");
		expect(result.errorDescription ?? "").not.toContain("decision service down");
	});

	it("answers a grantedScope past the requested scope 500", async () => {
		const { result } = await grantWith(async () => ({
			outcome: "allow",
			grantedScope: ["read", "admin"],
		})).handle(ctx({ scope: "read" }));
		expect(result).toMatchObject({ status: 500, error: "server_error" });
	});

	it("answers a grantedScope with the scope omitted 500: the ceiling is empty", async () => {
		const { result } = await grantWith(async () => ({
			outcome: "allow",
			grantedScope: ["read"],
		})).handle(ctx({}));
		expect(result).toMatchObject({ status: 500, error: "server_error" });
	});

	it("answers a grantedAudience outside allowedAudiences 500", async () => {
		const { result } = await grantWith(async () => ({
			outcome: "allow",
			grantedAudience: ["https://elsewhere"],
		})).handle(ctx());
		expect(result).toMatchObject({ status: 500, error: "server_error" });
	});

	it("is not consulted when admission refuses", async () => {
		const evaluate = vi.fn<GrantPolicyHook["evaluate"]>(async () => ({ outcome: "allow" }));
		const { result } = await grantWith(evaluate).handle(
			ctx(undefined, { session: { isAuthenticated: false } }),
		);
		expect(result.status).toBe(401);
		expect(evaluate).not.toHaveBeenCalled();
	});

	it("is not consulted when the requested scope is refused", async () => {
		const evaluate = vi.fn<GrantPolicyHook["evaluate"]>(async () => ({ outcome: "allow" }));
		const { result } = await grantWith(evaluate).handle(ctx({ scope: "admin" }));
		expect(result).toMatchObject({ status: 400, error: "invalid_scope" });
		expect(evaluate).not.toHaveBeenCalled();
	});
});

describe("session grant — grantPolicy narrows what is minted", () => {
	it("narrows named scopes to grantedScope", async () => {
		const { result } = await grantWith(async () => ({
			outcome: "allow",
			grantedScope: ["read"],
		})).handle(ctx({ scope: "read write" }));
		expect(minted(result).scope).toBe("read");
	});

	it("strips every scope on an empty grantedScope", async () => {
		const { result } = await grantWith(async () => ({ outcome: "allow", grantedScope: [] })).handle(
			ctx({ scope: "read write" }),
		);
		expect(minted(result).scope).toBeUndefined();
	});

	it("keeps an omitted scope omitted on an empty grantedScope", async () => {
		const { result } = await grantWith(async () => ({ outcome: "allow", grantedScope: [] })).handle(
			ctx({}),
		);
		expect(minted(result).scope).toBeUndefined();
	});

	it("keeps the requested scopes when the policy names none", async () => {
		const { result } = await grantWith(async () => ({ outcome: "allow" })).handle(
			ctx({ scope: "read write" }),
		);
		expect(minted(result).scope).toBe("read write");
	});

	it("mints for the policy's audience within allowedAudiences", async () => {
		const { result } = await grantWith(async () => ({
			outcome: "allow",
			grantedAudience: ["https://rs-b"],
		})).handle(ctx());
		expect(minted(result).aud).toBe("https://rs-b");
	});

	it("keeps the grant's own audience when the policy names none", async () => {
		const { result } = await grantWith(async () => ({ outcome: "allow" })).handle(ctx());
		expect(minted(result).aud).toBe("https://rs-a");
	});
});

describe("session grant — what the policy is asked", () => {
	it("hands it the authenticated client, the session's subject and the request context", async () => {
		const evaluate = vi.fn<GrantPolicyHook["evaluate"]>(async () => ({ outcome: "allow" }));
		await grantWith(evaluate).handle(ctx({ scope: "read", client_id: "spoofed" }));
		expect(evaluate).toHaveBeenCalledTimes(1);
		const [request, context] = evaluate.mock.calls[0] ?? [];
		expect(request).toEqual({
			grantType: "session",
			clientId: "app",
			subject: "user-1",
			requestedScope: ["read"],
		});
		expect(context).toEqual({
			ip: "203.0.113.7",
			userAgent: "test-agent",
			issuer: "https://issuer.test",
		});
	});

	it("hands it no requestedScope when the scope is omitted", async () => {
		const evaluate = vi.fn<GrantPolicyHook["evaluate"]>(async () => ({ outcome: "allow" }));
		await grantWith(evaluate).handle(ctx({}));
		expect(evaluate.mock.calls[0]?.[0].requestedScope).toBeUndefined();
	});

	it("cannot widen its own ceiling by writing to the request it is handed", async () => {
		const { result } = await grantWith(async (request) => {
			(request.requestedScope as string[]).push("write");
			return { outcome: "allow", grantedScope: ["read", "write"] };
		}).handle(ctx({ scope: "read" }));
		expect(result).toMatchObject({ status: 500, error: "server_error" });
	});
});

describe("session grant — the minting instant", () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	it("is taken after the policy answers, so a slow policy cannot shorten the token's life", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		const asked = Date.UTC(2026, 9, 2, 12, 0, 0);
		const answered = asked + 600_000;
		vi.setSystemTime(asked);
		const { result } = await grantWith(async () => {
			vi.setSystemTime(answered);
			return { outcome: "allow" };
		}).handle(ctx());
		const token = minted(result);
		expect(token.iat).toBe(answered / 1000);
		expect(token.exp).toBe(answered / 1000 + 3600);
	});

	it("refuses a tracked session that expires while the policy evaluates", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		const asked = Date.UTC(2026, 9, 2, 12, 0, 0);
		const answered = asked + 600_000;
		vi.setSystemTime(asked);
		const tracked: UserSession = {
			sid: "sid-1",
			sub: "user-1",
			authTime: new Date(asked - 300_000),
			createdAt: new Date(asked - 300_000),
			// Live when admitted, past by the time the policy answers.
			expiresAt: new Date(asked + 60_000),
			claims: {},
			amr: ["pwd"],
			authentication: {
				primary: "pwd",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: undefined,
			},
		};
		const userSessionStore = {
			kind: "memory",
			create: async () => {},
			get: async (sid: string) => (sid === tracked.sid ? tracked : null),
			delete: async () => {},
		} as unknown as UserSessionStore;
		const { result } = await createSessionGrant({
			sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
			config,
			keyStore: createSymmetricKeyStore("session-policy-test-secret-32-bytes"),
			userSessionStore,
			grantPolicy: {
				kind: "slow",
				evaluate: async () => {
					vi.setSystemTime(answered);
					return { outcome: "allow" };
				},
			},
		}).handle(
			ctx(undefined, {
				session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" } },
			}),
		);
		expect(result).toEqual({
			status: 400,
			error: "invalid_grant",
			errorDescription: "session_invalid",
		});
	});
});
