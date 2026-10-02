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
 * The device-code grant consults a wired `grantPolicy` at the poll, after the
 * approval is read and checked, before minting, with core's fail-closed rules:
 * deny is 400 with the policy's error when it is a token-endpoint code
 * (`invalid_grant` otherwise), a throw is 503, a scope or audience past
 * the ceiling is 500. `poll` has consumed the approval by then, so each of
 * those spends it.
 */

import type {
	AuthenticatedClient,
	GrantContext,
	GrantHandlerResult,
	GrantPolicyHook,
	SubjectRevocation,
} from "@o3co/auth-provider-core";
import {
	consoleLogger,
	createMemoryDeviceCodeStore,
	createSymmetricKeyStore,
} from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { describe, expect, it, type Mock, vi } from "vitest";
import { createDeviceCodeGrant } from "#/grant.mjs";
import { DEVICE_CODE_GRANT_TYPE } from "#/types.mjs";

const NOW = 1_800_000_000_000;
const ISSUER = "https://as.example.test";

const client = {
	clientId: "tv-app",
	tokenEndpointAuthMethod: "none" as const,
	allowedScopes: ["openid", "profile"],
	allowedAudiences: ["https://api-a.example.test", "https://api-b.example.test"],
	allowedGrantTypes: [DEVICE_CODE_GRANT_TYPE],
} as unknown as AuthenticatedClient;

/** An approved device code in a consuming store, and a grant over it that asks `evaluate`. */
const approvedWith = async (
	evaluate: GrantPolicyHook["evaluate"],
	grantedScope: readonly string[] | undefined = ["openid", "profile"],
	subjectRevocation?: SubjectRevocation,
	logger?: { warn: Mock<(obj: Record<string, unknown>, msg: string) => void>; error: Mock },
) => {
	const store = createMemoryDeviceCodeStore();
	await store.create({
		deviceCode: "device-code-1",
		userCode: "BCDFGHJK",
		clientId: client.clientId,
		requestedScope: grantedScope,
		expiresAtMs: NOW + 600_000,
		intervalSeconds: 5,
	});
	const approval = await store.approve({
		userCode: "BCDFGHJK",
		subject: "user-1",
		nowMs: NOW,
		...(grantedScope === undefined ? {} : { grantedScope }),
	});
	expect(approval.status).toBe("ok");
	const grant = createDeviceCodeGrant({
		store,
		keyStore: createSymmetricKeyStore("device-policy-test-secret-32-bytes!"),
		accessTokenExpiresIn: 300,
		now: () => NOW + 10_000,
		grantPolicy: { kind: "stub", evaluate },
		...(subjectRevocation === undefined ? {} : { subjectRevocation }),
		...(logger === undefined ? {} : { logger }),
	});
	const poll = (authenticatedClient: AuthenticatedClient = client) =>
		grant.handle({
			body: { device_code: "device-code-1" },
			session: {},
			metadata: {},
			issuer: ISSUER,
			ip: "203.0.113.9",
			userAgent: "tv-agent",
			authenticatedClient,
		} as GrantContext);
	return { poll };
};

const minted = ({ result }: GrantHandlerResult) => {
	if (!("tokens" in result)) throw new Error(`expected tokens, got ${JSON.stringify(result)}`);
	return decodeJwt(result.tokens.access_token);
};

describe("device-code grant — grantPolicy refusals at the poll", () => {
	it("answers a deny 400 with the policy's own error", async () => {
		const { poll } = await approvedWith(async () => ({
			outcome: "deny",
			error: "invalid_scope",
			errorDescription: "devices are closed",
		}));
		expect((await poll()).result).toEqual({
			status: 400,
			error: "invalid_scope",
			errorDescription: "devices are closed",
		});
	});

	it.each(["authorization_pending", "slow_down", "expired_token", "access_denied"])(
		"answers a deny with the RFC 8628 polling code %s invalid_grant, so the device stops polling a spent approval",
		async (code) => {
			const logger = { warn: vi.fn(), error: vi.fn() };
			const { poll } = await approvedWith(
				async () => ({ outcome: "deny", error: code, errorDescription: "devices are closed" }),
				undefined,
				undefined,
				logger,
			);
			expect((await poll()).result).toEqual({
				status: 400,
				error: "invalid_grant",
				errorDescription: "devices are closed",
			});
			expect(logger.warn).toHaveBeenCalledWith(
				expect.objectContaining({ error: code, answered: "invalid_grant" }),
				"grant_policy_refusal_rewritten",
			);
		},
	);

	it("repairs a deny's description to RFC 6749 §5.2's characters", async () => {
		const { poll } = await approvedWith(async () => ({
			outcome: "deny",
			error: "invalid_scope",
			errorDescription: 'devices are "closed"',
		}));
		expect((await poll()).result).toEqual({
			status: 400,
			error: "invalid_scope",
			errorDescription: "devices are ?closed?",
		});
	});

	it("leaves the rewrite line to core's console logger when the grant's logger has no warn function", async () => {
		const spy = vi.spyOn(consoleLogger, "warn").mockImplementation(() => {});
		try {
			const logger = { warn: undefined, error: vi.fn() } as unknown as {
				warn: Mock<(obj: Record<string, unknown>, msg: string) => void>;
				error: Mock;
			};
			const { poll } = await approvedWith(
				async () => ({ outcome: "deny", error: "consent_required" }),
				undefined,
				undefined,
				logger,
			);
			expect((await poll()).result).toEqual({ status: 400, error: "invalid_grant" });
			expect(spy.mock.calls.map((call) => call[1])).toEqual(["grant_policy_refusal_rewritten"]);
		} finally {
			spy.mockRestore();
		}
	});

	it("answers a policy that throws 503", async () => {
		const { poll } = await approvedWith(async () => {
			throw new Error("decision service down");
		});
		expect((await poll()).result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
	});

	it("answers a policy that throws synchronously 503", async () => {
		const { poll } = await approvedWith(() => {
			throw new Error("decision service down");
		});
		expect((await poll()).result).toMatchObject({ status: 503, error: "temporarily_unavailable" });
	});

	it("answers a grantedScope on an approval of no scope 500, not a widened token", async () => {
		const { poll } = await approvedWith(
			async () => ({ outcome: "allow", grantedScope: ["openid"] }),
			[],
		);
		expect((await poll()).result).toMatchObject({ status: 500, error: "server_error" });
	});

	it("answers a grantedScope past the approved scope 500", async () => {
		const { poll } = await approvedWith(
			async () => ({ outcome: "allow", grantedScope: ["openid", "admin"] }),
			["openid"],
		);
		expect((await poll()).result).toMatchObject({ status: 500, error: "server_error" });
	});

	it("answers a grantedAudience outside allowedAudiences 500", async () => {
		const { poll } = await approvedWith(async () => ({
			outcome: "allow",
			grantedAudience: ["https://elsewhere.example.test"],
		}));
		expect((await poll()).result).toMatchObject({ status: 500, error: "server_error" });
	});

	it("has spent the approval after a deny: a re-poll is invalid_grant", async () => {
		const { poll } = await approvedWith(async () => ({ outcome: "deny", error: "invalid_scope" }));
		expect((await poll()).result).toMatchObject({ status: 400, error: "invalid_scope" });
		expect((await poll()).result).toMatchObject({ status: 400, error: "invalid_grant" });
	});

	it("has spent the approval after a 503: a re-poll is invalid_grant", async () => {
		const evaluate = vi.fn<GrantPolicyHook["evaluate"]>(async () => {
			throw new Error("decision service down");
		});
		const { poll } = await approvedWith(evaluate);
		expect((await poll()).result).toMatchObject({ status: 503 });
		expect((await poll()).result).toMatchObject({ status: 400, error: "invalid_grant" });
		expect(evaluate).toHaveBeenCalledTimes(1);
	});
});

describe("device-code grant — grantPolicy narrows what is minted", () => {
	it("narrows the approved scope to grantedScope", async () => {
		const { poll } = await approvedWith(async () => ({
			outcome: "allow",
			grantedScope: ["openid"],
		}));
		expect(minted(await poll()).scope).toBe("openid");
	});

	it("strips every scope on an empty grantedScope", async () => {
		const { poll } = await approvedWith(async () => ({ outcome: "allow", grantedScope: [] }));
		expect(minted(await poll()).scope).toBeUndefined();
	});

	it("mints for the policy's audience within allowedAudiences", async () => {
		const { poll } = await approvedWith(async () => ({
			outcome: "allow",
			grantedAudience: ["https://api-b.example.test"],
		}));
		expect(minted(await poll()).aud).toBe("https://api-b.example.test");
	});

	it("keeps the grant's own audience when the policy names none", async () => {
		const { poll } = await approvedWith(async () => ({ outcome: "allow" }));
		expect(minted(await poll()).aud).toBe("https://api-a.example.test");
	});
});

describe("device-code grant — what the policy is asked", () => {
	it("hands it the authenticated client, the approving subject, the approved scope and the context", async () => {
		const evaluate = vi.fn<GrantPolicyHook["evaluate"]>(async () => ({ outcome: "allow" }));
		const { poll } = await approvedWith(evaluate);
		await poll();
		expect(evaluate).toHaveBeenCalledTimes(1);
		const [request, context] = evaluate.mock.calls[0] ?? [];
		expect(request).toEqual({
			grantType: DEVICE_CODE_GRANT_TYPE,
			clientId: "tv-app",
			subject: "user-1",
			requestedScope: ["openid", "profile"],
		});
		expect(context).toEqual({ ip: "203.0.113.9", userAgent: "tv-agent", issuer: ISSUER });
	});

	it("is not consulted for a poll that is not approved", async () => {
		const evaluate = vi.fn<GrantPolicyHook["evaluate"]>(async () => ({ outcome: "allow" }));
		const store = createMemoryDeviceCodeStore();
		const grant = createDeviceCodeGrant({
			store,
			keyStore: createSymmetricKeyStore("device-policy-test-secret-32-bytes!"),
			accessTokenExpiresIn: 300,
			grantPolicy: { kind: "stub", evaluate },
		});
		const { result } = await grant.handle({
			body: { device_code: "unknown" },
			session: {},
			metadata: {},
			issuer: ISSUER,
			authenticatedClient: client,
		} as GrantContext);
		expect(result).toMatchObject({ status: 400, error: "invalid_grant" });
		expect(evaluate).not.toHaveBeenCalled();
	});

	it("is not consulted for an approval issued to another client", async () => {
		const evaluate = vi.fn<GrantPolicyHook["evaluate"]>(async () => ({ outcome: "allow" }));
		const { poll } = await approvedWith(evaluate);
		const other = { ...client, clientId: "other-app" } as AuthenticatedClient;
		expect((await poll(other)).result).toMatchObject({ status: 400, error: "invalid_grant" });
		expect(evaluate).not.toHaveBeenCalled();
	});

	it("is not consulted for a pending code, at authorization_pending or slow_down", async () => {
		const evaluate = vi.fn<GrantPolicyHook["evaluate"]>(async () => ({ outcome: "allow" }));
		const store = createMemoryDeviceCodeStore();
		await store.create({
			deviceCode: "device-code-1",
			userCode: "BCDFGHJK",
			clientId: client.clientId,
			requestedScope: ["openid"],
			expiresAtMs: NOW + 600_000,
			intervalSeconds: 5,
		});
		const grant = createDeviceCodeGrant({
			store,
			keyStore: createSymmetricKeyStore("device-policy-test-secret-32-bytes!"),
			accessTokenExpiresIn: 300,
			now: () => NOW + 10_000,
			grantPolicy: { kind: "stub", evaluate },
		});
		const poll = async () =>
			(
				await grant.handle({
					body: { device_code: "device-code-1" },
					session: {},
					metadata: {},
					issuer: ISSUER,
					authenticatedClient: client,
				} as GrantContext)
			).result;
		expect(await poll()).toMatchObject({ status: 400, error: "authorization_pending" });
		expect(await poll()).toMatchObject({ status: 400, error: "slow_down" });
		expect(evaluate).not.toHaveBeenCalled();
	});

	it("cannot widen its own ceiling by writing to the request it is handed", async () => {
		const { poll } = await approvedWith(
			async (request) => {
				(request.requestedScope as string[]).push("profile");
				return { outcome: "allow", grantedScope: ["openid", "profile"] };
			},
			["openid"],
		);
		expect((await poll()).result).toMatchObject({ status: 500, error: "server_error" });
	});
});

describe("device-code grant — the minting instant", () => {
	it("is taken after the policy answers, so a slow policy cannot shorten the token's life", async () => {
		const store = createMemoryDeviceCodeStore();
		await store.create({
			deviceCode: "device-code-1",
			userCode: "BCDFGHJK",
			clientId: client.clientId,
			requestedScope: ["openid"],
			expiresAtMs: NOW + 600_000,
			intervalSeconds: 5,
		});
		await store.approve({ userCode: "BCDFGHJK", subject: "user-1", nowMs: NOW });
		let clock = NOW + 10_000;
		const answered = clock + 600_000;
		const grant = createDeviceCodeGrant({
			store,
			keyStore: createSymmetricKeyStore("device-policy-test-secret-32-bytes!"),
			accessTokenExpiresIn: 300,
			now: () => clock,
			grantPolicy: {
				kind: "slow",
				evaluate: async () => {
					clock = answered;
					return { outcome: "allow" };
				},
			},
		});
		const token = minted(
			await grant.handle({
				body: { device_code: "device-code-1" },
				session: {},
				metadata: {},
				issuer: ISSUER,
				authenticatedClient: client,
			} as GrantContext),
		);
		expect(token.iat).toBe(answered / 1000);
		expect(token.exp).toBe(answered / 1000 + 300);
	});
});

describe("device-code grant — the revocation boundary is read after the policy answers", () => {
	it("refuses an approval a revocation landing while the policy evaluates covers", async () => {
		// A boundary on the fixture's clock: a store clamps one to its own.
		let boundary: Date | null = null;
		const subjectRevocation: SubjectRevocation = {
			kind: "stub",
			revokeBefore: async () => {},
			revokedBefore: async () => boundary,
		};
		const { poll } = await approvedWith(
			async () => {
				boundary = new Date(NOW + 5_000);
				return { outcome: "allow" };
			},
			["openid"],
			subjectRevocation,
		);
		expect((await poll()).result).toMatchObject({ status: 400, error: "invalid_grant" });
	});
});
