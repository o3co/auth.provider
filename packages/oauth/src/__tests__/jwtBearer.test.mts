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
 * Issue #301 — the public entry point for "present a device credential →
 * authenticate → get tokens".
 *
 * `authenticateByToken` existed and was service-pluggable, but only the
 * federation callback called it, so there was no way in. These pin the grant
 * that opens it and, more importantly, the things it refuses: the issue is
 * emphatic that a bare identifier must never be a login, and that the identity
 * lifecycle stays with the Store.
 */

import { generateKeyPairSync } from "node:crypto";
import {
	type AppConfig,
	type AssertionVerifier,
	type AuthenticatedClient,
	createJwtAssertionVerifier,
	createMemoryAssertionIssuerRegistry,
	createMemoryReplaySeenSet,
	createRegistryAssertionVerifier,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantPolicyDecision,
	type GrantPolicyHook,
	type GrantResult,
	type UserRepository,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { decodeJwt, SignJWT } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createJwtBearerGrant, JWT_BEARER_GRANT_TYPE } from "#/grants/jwtBearer.mjs";
import { oauthAuthorizationModule } from "#/oauthAuthorization.mjs";

const keyStore = createSymmetricKeyStore("test-secret-at-least-32-chars!!");
const config = {
	oauth: { jwt: { issuer: "https://auth.example" }, accessToken: { expiresIn: 300 } },
} as unknown as AppConfig;

/** Verifies anything, returning the handle it is told to. Possession stands in. */
const verifierFor = (
	result: Awaited<ReturnType<AssertionVerifier["verify"]>>,
	overrides: Partial<AssertionVerifier> = {},
): AssertionVerifier => ({ kind: "stub", verify: async () => result, ...overrides });

const userRepoFor = (user: unknown): UserRepository =>
	({
		authenticate: async () => null,
		authenticateByToken: async () => user,
	}) as unknown as UserRepository;

const build = (opts: {
	verifier?: AssertionVerifier;
	userRepository?: UserRepository;
	logger?: unknown;
	config?: AppConfig;
	grantPolicy?: GrantPolicyHook;
}) =>
	createJwtBearerGrant({
		config: opts.config ?? config,
		keyStore,
		assertionVerifier: opts.verifier ?? verifierFor({ subjectHandle: "device:abc" }),
		userRepository: opts.userRepository ?? userRepoFor({ id: "u-1" }),
		...(opts.logger ? { logger: opts.logger } : {}),
		...(opts.grantPolicy ? { grantPolicy: opts.grantPolicy } : {}),
	} as never);

const ctx = (body: Record<string, unknown> = {}, extra: Partial<GrantContext> = {}): GrantContext =>
	({
		body: { assertion: "an-assertion", ...body },
		session: {},
		issuer: "https://auth.example",
		metadata: {},
		authenticatedClient: null,
		...extra,
	}) as GrantContext;

const policyOf = (
	evaluate: (...args: Parameters<GrantPolicyHook["evaluate"]>) => Promise<GrantPolicyDecision>,
): GrantPolicyHook => ({ kind: "stub", evaluate });
const allow = (extra: Record<string, unknown> = {}) =>
	policyOf(async () => ({ ...extra, outcome: "allow" }) as GrantPolicyDecision);

describe("jwt-bearer grant — the happy path (#301)", () => {
	it("uses the registered RFC 7523 grant type", () => {
		expect(JWT_BEARER_GRANT_TYPE).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
	});

	it("issues a token whose sub is what the Store resolved, not the handle", async () => {
		// The boundary in one assertion: the verifier proves possession of
		// `device:abc`; who that *is* comes from the Store.
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "device:abc" }),
			userRepository: userRepoFor({ id: "user-42" }),
		}).handle(ctx());

		expect(result.status).toBe(200);
		if (!("tokens" in result)) expect.fail("expected tokens");
		expect(decodeJwt(result.tokens.access_token as string).sub).toBe("user-42");
	});

	it("mints the configured default lifetime and ignores an expires_in request parameter", async () => {
		const { result } = await build({
			config: {
				oauth: {
					jwt: { issuer: "https://auth.example" },
					accessToken: { defaultExpiresIn: 600, maxExpiresIn: 7200 },
				},
			} as unknown as AppConfig,
		}).handle(ctx({ expires_in: "7200" }));

		if (!("tokens" in result)) expect.fail("expected tokens");
		expect(result.tokens.expires_in).toBe(600);
		const payload = decodeJwt(result.tokens.access_token as string);
		expect((payload.exp as number) - (payload.iat as number)).toBe(600);
	});

	it("hands the Store exactly the handle the verifier returned", async () => {
		const authenticateByToken = vi.fn(async () => ({ id: "u-1" }));
		await build({
			verifier: verifierFor({ subjectHandle: "device:abc" }),
			userRepository: { authenticate: async () => null, authenticateByToken } as never,
		}).handle(ctx());
		expect(authenticateByToken).toHaveBeenCalledWith("device:abc");
	});

	it("never lets the request supply the handle", async () => {
		// The request carries an assertion, never an identifier. If a body
		// field could become the handle, the grant would be a string comparison.
		const authenticateByToken = vi.fn(async () => ({ id: "u-1" }));
		await build({
			verifier: verifierFor({ subjectHandle: "device:from-verifier" }),
			userRepository: { authenticate: async () => null, authenticateByToken } as never,
		}).handle(ctx({ subject_handle: "device:attacker", sub: "admin" }));
		expect(authenticateByToken).toHaveBeenCalledWith("device:from-verifier");
	});

	it("declares requiresExplicitGrantAllowlist: true on the handler contract (#326)", () => {
		// A device credential is a standing capability of a registration, not a
		// per-user ceremony: like client_credentials and the device grant, a
		// client registered before `allowedGrantTypes` existed must not acquire
		// it by omission. Dispatch refuses an absent allowlist for handlers
		// that declare this; an unauthenticated caller has no allowlist to
		// consult and is unaffected.
		expect(build({}).requiresExplicitGrantAllowlist).toBe(true);
	});

	it("works without an authenticated client — RFC 7523 §3 makes that optional", async () => {
		// The property token exchange refuses ("does not support public
		// clients") and the reason this is a separate grant.
		const { result } = await build({}).handle(ctx({}, { authenticatedClient: null }));
		expect(result.status).toBe(200);
	});

	it("issues an anonymous subject when the Store returns one for an unlinked device", async () => {
		// anonymous→registered needs no lifecycle here: the Store decides what
		// an unlinked handle resolves to, and continuity is its data model.
		const { result } = await build({
			userRepository: userRepoFor({ id: "device:abc" }),
		}).handle(ctx());
		if (!("tokens" in result)) expect.fail("expected tokens");
		expect(decodeJwt(result.tokens.access_token as string).sub).toBe("device:abc");
	});
});

describe("jwt-bearer grant — what it refuses (#301)", () => {
	it("answers invalid_request for a missing assertion", async () => {
		// RFC 6749 §5.2: a missing parameter is not a bad grant.
		const { result } = await build({}).handle(ctx({ assertion: undefined }));
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_request");
	});

	it("answers invalid_request for a blank or non-string assertion", async () => {
		for (const assertion of ["", 42, null, ["a"]]) {
			const { result } = await build({}).handle(ctx({ assertion }));
			expect("error" in result && result.error).toBe("invalid_request");
		}
	});

	it("answers invalid_grant when the assertion does not verify", async () => {
		const { result } = await build({ verifier: verifierFor(null) }).handle(ctx());
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
	});

	it("answers invalid_grant when the Store does not know the handle", async () => {
		const { result } = await build({ userRepository: userRepoFor(null) }).handle(ctx());
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
	});

	it("says the same thing either way — the two are not distinguishable", async () => {
		// Telling them apart is a probe for which device identifiers exist.
		const unverified = await build({ verifier: verifierFor(null) }).handle(ctx());
		const unknown = await build({ userRepository: userRepoFor(null) }).handle(ctx());
		expect(unverified.result).toEqual(unknown.result);
	});

	it("refuses a resolved user carrying no id rather than minting an empty sub", async () => {
		// A token whose `sub` is "" names nobody and would verify.
		const { result } = await build({ userRepository: userRepoFor({ id: "" }) }).handle(ctx());
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
	});
});

describe("jwt-bearer grant — oauth.requireEmailVerified (#297)", () => {
	// The third point that holds a resolved user at issuance, after
	// `/authorize` and the `session` grant. A deployment that turned the gate
	// on would otherwise find two paths gated and this one wide open.
	const gated = {
		...config,
		oauth: { ...config.oauth, requireEmailVerified: true },
	} as unknown as AppConfig;

	it("refuses when the gate is on and the Store published no verification", async () => {
		const { result } = await build({
			config: gated,
			userRepository: userRepoFor({ id: "u-1" }),
		}).handle(ctx());
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
	});

	it("refuses when the Store published an explicit false", async () => {
		const { result } = await build({
			config: gated,
			userRepository: userRepoFor({ id: "u-1", emailVerified: false }),
		}).handle(ctx());
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
	});

	it("admits when the Store published true", async () => {
		const { result } = await build({
			config: gated,
			userRepository: userRepoFor({ id: "u-1", emailVerified: true }),
		}).handle(ctx());
		expect(result.status).toBe(200);
	});

	it("is inert when the gate is off, whatever the Store published", async () => {
		// Off is the default, and a Store that does not model the field must be
		// entirely unaffected.
		const { result } = await build({
			userRepository: userRepoFor({ id: "u-1", emailVerified: false }),
		}).handle(ctx());
		expect(result.status).toBe(200);
	});

	it("answers exactly what an unknown handle answers, so it cannot be probed", async () => {
		// A different description would tell a caller that this handle resolves
		// to a real, merely unverified, account.
		const unverified = await build({
			config: gated,
			userRepository: userRepoFor({ id: "u-1" }),
		}).handle(ctx());
		const unknown = await build({ userRepository: userRepoFor(null) }).handle(ctx());
		expect(unverified.result).toEqual(unknown.result);
	});
});

describe("jwt-bearer grant — outage is not refusal (#301)", () => {
	it("answers 503 when the verifier cannot reach a conclusion", async () => {
		// An attestation service being down is not a bad credential. Answering
		// invalid_grant would send an operator to re-enrol a device that was
		// fine — the distinction #408 drew for revocation stores.
		const { result } = await build({
			verifier: verifierFor(null, {
				verify: async () => {
					throw new Error("attestation service unreachable");
				},
			}),
		}).handle(ctx());
		expect(result.status).toBe(503);
		expect("error" in result && result.error).toBe("temporarily_unavailable");
	});

	it("answers 503 when the Store is unreachable", async () => {
		const { result } = await build({
			userRepository: {
				authenticate: async () => null,
				authenticateByToken: async () => {
					throw new Error("ECONNREFUSED");
				},
			} as never,
		}).handle(ctx());
		expect(result.status).toBe(503);
	});

	it("logs the cause rather than swallowing it", async () => {
		const error = vi.fn();
		await build({
			logger: { error, warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
			verifier: verifierFor(null, {
				verify: async () => {
					throw new Error("boom");
				},
			}),
		}).handle(ctx());
		// The cause, as core's projection of it: logged, and never as it came.
		expect(error).toHaveBeenCalledWith(
			expect.objectContaining({ err: expect.objectContaining({ name: "Error", detail: "boom" }) }),
			expect.stringContaining("assertion_verifier_unavailable"),
		);
	});
});

describe("jwt-bearer grant — scope is a ceiling, never a grant (#301)", () => {
	it("intersects the request with what the assertion authorizes", async () => {
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "d", scope: ["read", "write"] }),
		}).handle(ctx({ scope: "read" }));
		if (!("tokens" in result)) expect.fail("expected tokens");
		expect(decodeJwt(result.tokens.access_token as string).scope).toBe("read");
	});

	it("refuses a scope the assertion does not authorize", async () => {
		// Silently narrowing would hand back a token that does less than the
		// caller believes, which surfaces as a permission bug much later.
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "d", scope: ["read"] }),
		}).handle(ctx({ scope: "read admin" }));
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_scope");
	});

	it("refuses a scope the client is not allowed, even if the assertion allows it", async () => {
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "d", scope: ["read", "admin"] }),
		}).handle(
			ctx({ scope: "admin" }, {
				authenticatedClient: { clientId: "c1", allowedScopes: ["read"] },
			} as never),
		);
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_scope");
	});

	it("grants nothing when no ceiling exists and none is requested", async () => {
		// An absent ceiling constrains nothing; it must not become a licence to
		// take everything, which is the over-grant #396 removed elsewhere.
		const { result } = await build({}).handle(ctx());
		if (!("tokens" in result)) expect.fail("expected tokens");
		expect(decodeJwt(result.tokens.access_token as string).scope).toBeUndefined();
	});

	it("refuses a requested scope when nothing bounds it", async () => {
		// The fail-OPEN this had: `within` is `ceilings.every(...)` and
		// `[].every(...)` is true, so an assertion that names no scope plus no
		// authenticated client meant the caller got whatever they asked for.
		// Found in review; the comment two paragraphs up claimed the opposite.
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "d" }),
		}).handle(ctx({ scope: "admin" }, { authenticatedClient: null }));
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_scope");
	});

	it("says why nothing bounds it, rather than just refusing", async () => {
		const { result } = await build({}).handle(ctx({ scope: "read" }));
		const description = "errorDescription" in result ? result.errorDescription : "";
		expect(description).toMatch(/assertion names no scope/);
		expect(description).toMatch(/no authenticated client/);
	});

	it("still grants nothing — not everything — when no scope is requested either", async () => {
		const { result } = await build({}).handle(ctx());
		if (!("tokens" in result)) expect.fail("expected tokens");
		expect(decodeJwt(result.tokens.access_token as string).scope).toBeUndefined();
	});

	it("accepts a request bounded by the client alone", async () => {
		// One ceiling is enough; the refusal above is about having none.
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "d" }),
		}).handle(
			ctx({ scope: "read" }, {
				authenticatedClient: { clientId: "c1", allowedScopes: ["read", "write"] },
			} as never),
		);
		expect(result.status).toBe(200);
	});

	it("reads scope: null as an omitted scope, and refuses any other value that is not a string", async () => {
		// RFC 6749 §3.2: a parameter sent without a value is treated as
		// omitted. A JSON body's `null` is that, as `scope=""` is for a form
		// body — the same reading token exchange gives `expires_in: null`. Any
		// other value that is not a string is `invalid_request`.
		const client = {
			authenticatedClient: {
				clientId: "c1",
				allowedScopes: ["read", "write"],
				defaultScopes: ["read"],
			},
		} as never;
		const grant = build({
			verifier: verifierFor({ subjectHandle: "d", scope: ["read", "write"] }),
		});
		const omitted = (await grant.handle(ctx({}, client))).result;
		const nulled = (await grant.handle(ctx({ scope: null }, client))).result;
		if (!("tokens" in omitted) || !("tokens" in nulled)) expect.fail("expected tokens");
		expect(decodeJwt(nulled.tokens.access_token as string).scope).toBe("read");
		expect(decodeJwt(omitted.tokens.access_token as string).scope).toBe("read");

		for (const scope of [42, {}, true]) {
			const { result } = await grant.handle(ctx({ scope }, client));
			expect("error" in result && result.error, JSON.stringify(scope)).toBe("invalid_request");
		}
	});

	it("rejects a non-string scope", async () => {
		const { result } = await build({}).handle(ctx({ scope: ["read"] }));
		expect("error" in result && result.error).toBe("invalid_request");
	});

	it("refuses a scope that is not RFC 6749 §3.3's space-delimited list as malformed", async () => {
		// A client's request is read strictly: a tab is not a delimiter, and a
		// scope-token cannot hold a quote. invalid_scope (§5.2: "malformed"),
		// saying so, rather than a verdict on a scope named "read\twrite".
		const verifier = verifierFor({ subjectHandle: "d", scope: ["read", "write"] });
		for (const scope of ["read\twrite", 'read "write"', "\t"]) {
			const { result } = await build({ verifier }).handle(ctx({ scope }));
			expect(result.status, JSON.stringify(scope)).toBe(400);
			expect("error" in result && result.error).toBe("invalid_scope");
			expect("errorDescription" in result && result.errorDescription).toBe(
				"scope is not a space-delimited list of scope-tokens",
			);
		}
	});
});

describe("jwt-bearer grant — an omitted scope draws on defaultScopes, never the allowlist (#396)", () => {
	const client = (over: Record<string, unknown>) =>
		({ authenticatedClient: { clientId: "c1", ...over } }) as never;
	const scopeOf = (result: { status: number } & Record<string, unknown>) =>
		"tokens" in result
			? decodeJwt((result.tokens as { access_token: string }).access_token).scope
			: expect.fail("expected tokens");

	it("refuses an omitted scope for a client that declares no defaultScopes", async () => {
		// The over-grant #396 removed from client_credentials: "forgot to send
		// scope" used to be the maximum grant. An authenticated client with an
		// allowlist and no declared default gets invalid_scope, not the
		// allowlist.
		const { result } = await build({}).handle(
			ctx({}, client({ allowedScopes: ["read", "write"] })),
		);
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_scope");
		expect("errorDescription" in result && result.errorDescription).toMatch(/defaultScopes/);
	});

	it("refuses it even when the assertion names a scope — the assertion is a ceiling, not a default", async () => {
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "d", scope: ["read"] }),
		}).handle(ctx({}, client({ allowedScopes: ["read", "write"] })));
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_scope");
	});

	it("grants the client's defaultScopes when scope is omitted", async () => {
		const { result } = await build({}).handle(
			ctx({}, client({ allowedScopes: ["read", "write"], defaultScopes: ["read"] })),
		);
		expect(result.status).toBe(200);
		expect(scopeOf(result)).toBe("read");
	});

	it("bounds the defaultScopes by what the assertion authorizes", async () => {
		// The assertion stays a ceiling on the declared default: a device whose
		// credential says "read" does not get "write" because the client's
		// registration would default to it.
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "d", scope: ["read"] }),
		}).handle(
			ctx({}, client({ allowedScopes: ["read", "write"], defaultScopes: ["read", "write"] })),
		);
		expect(result.status).toBe(200);
		expect(scopeOf(result)).toBe("read");
	});

	it("filters the defaultScopes by the allowlist even so", async () => {
		// Schema-validated registrations are a subset by boot; a custom
		// repository is under no such obligation.
		const { result } = await build({}).handle(
			ctx({}, client({ allowedScopes: ["read"], defaultScopes: ["read", "admin"] })),
		);
		expect(result.status).toBe(200);
		expect(scopeOf(result)).toBe("read");
	});

	it("keeps the empty grant for a scope-less client (empty allowlist, no defaults)", async () => {
		// Nothing to over-grant, so nothing to refuse.
		const { result } = await build({}).handle(ctx({}, client({ allowedScopes: [] })));
		expect(result.status).toBe(200);
		expect(scopeOf(result)).toBeUndefined();
	});

	it("treats a blank scope exactly like an omitted one", async () => {
		const { result } = await build({}).handle(
			ctx({ scope: "" }, client({ allowedScopes: ["read", "write"] })),
		);
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_scope");
	});

	it("without a client, an omitted scope receives what the assertion itself declares", async () => {
		// No registration is present to declare a default, so the assertion's
		// issuer is the only authority in the room and its `scope` claim is the
		// declared default. Unchanged from #428, pinned so it is a decision.
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "d", scope: ["read"] }),
		}).handle(ctx({}, { authenticatedClient: null }));
		expect(result.status).toBe(200);
		expect(scopeOf(result)).toBe("read");
	});
});

describe("jwt-bearer grant — grantPolicy is consulted, fail-closed (CP-18)", () => {
	// Every other minting path evaluates `grantPolicy`; this one did not, so
	// a deployment's policy hook saw client_credentials, refresh_token, the
	// code flow and token exchange — and never a device login.
	const authed = {
		authenticatedClient: {
			clientId: "c1",
			allowedScopes: ["read", "write"],
			defaultScopes: ["read", "write"],
		},
	} as never;
	const scopeOf = (result: { status: number } & Record<string, unknown>) =>
		"tokens" in result
			? decodeJwt((result.tokens as { access_token: string }).access_token).scope
			: expect.fail("expected tokens");

	it("evaluates the policy with the grant type, the client and the resolved subject", async () => {
		const evaluate = vi.fn(async (): Promise<GrantPolicyDecision> => ({ outcome: "allow" }));
		await build({
			grantPolicy: policyOf(evaluate),
			userRepository: userRepoFor({ id: "user-42" }),
		}).handle(ctx({ scope: "read" }, authed));
		expect(evaluate).toHaveBeenCalledWith(
			expect.objectContaining({
				grantType: JWT_BEARER_GRANT_TYPE,
				clientId: "c1",
				subject: "user-42",
				requestedScope: ["read"],
			}),
			expect.objectContaining({ issuer: "https://auth.example" }),
		);
	});

	it("consults the policy for an unauthenticated caller too, with no clientId", async () => {
		// RFC 7523 §3 makes client authentication optional; policy is not.
		const evaluate = vi.fn(async (): Promise<GrantPolicyDecision> => ({ outcome: "allow" }));
		await build({ grantPolicy: policyOf(evaluate) }).handle(ctx({}, { authenticatedClient: null }));
		expect(evaluate).toHaveBeenCalledTimes(1);
		expect(evaluate.mock.calls[0]?.[0]).toMatchObject({ clientId: undefined, subject: "u-1" });
	});

	it("passes an omitted scope to the policy as undefined, not as an empty list", async () => {
		const evaluate = vi.fn(async (): Promise<GrantPolicyDecision> => ({ outcome: "allow" }));
		await build({ grantPolicy: policyOf(evaluate) }).handle(ctx());
		expect(evaluate.mock.calls[0]?.[0]).toMatchObject({ requestedScope: undefined });
	});

	it("denies with the policy's own error and description", async () => {
		const { result } = await build({
			grantPolicy: policyOf(async () => ({
				outcome: "deny",
				error: "access_denied",
				errorDescription: "device is quarantined",
			})),
		}).handle(ctx({ scope: "read" }, authed));
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("access_denied");
		expect("errorDescription" in result && result.errorDescription).toBe("device is quarantined");
	});

	it("answers 503 when the policy throws — fail closed, never open", async () => {
		// Policy is a security boundary: if it cannot answer, the pre-policy
		// ceiling must not become the grant.
		const { result } = await build({
			grantPolicy: policyOf(async () => {
				throw new Error("policy service unreachable");
			}),
		}).handle(ctx({ scope: "read" }, authed));
		expect(result.status).toBe(503);
		expect("error" in result && result.error).toBe("temporarily_unavailable");
	});

	it("narrows the scope to what the policy grants", async () => {
		const { result } = await build({ grantPolicy: allow({ grantedScope: ["read"] }) }).handle(
			ctx({ scope: "read write" }, authed),
		);
		expect(result.status).toBe(200);
		expect(scopeOf(result)).toBe("read");
	});

	it("honours an empty grantedScope as strip-all", async () => {
		const { result } = await build({ grantPolicy: allow({ grantedScope: [] }) }).handle(
			ctx({ scope: "read write" }, authed),
		);
		expect(result.status).toBe(200);
		expect(scopeOf(result)).toBeUndefined();
	});

	it("refuses a policy that widens past the effective scope, even within the allowlist", async () => {
		// `write` is in the client's allowlist but was not requested: a policy
		// returning it is scope expansion, and a compromised policy must not
		// be able to hand out more than the caller asked for.
		const { result } = await build({
			grantPolicy: allow({ grantedScope: ["read", "write"] }),
		}).handle(ctx({ scope: "read" }, authed));
		// #520: the policy exceeded its authority, the caller did not.
		expect(result.status).toBe(500);
		expect("error" in result && result.error).toBe("server_error");
	});

	it("leaves the effective scope alone when the policy says nothing about it", async () => {
		const { result } = await build({ grantPolicy: allow() }).handle(
			ctx({ scope: "read write" }, authed),
		);
		expect(scopeOf(result)).toBe("read write");
	});

	it("runs after the identity gates: an unverified assertion never reaches the policy", async () => {
		const evaluate = vi.fn(async (): Promise<GrantPolicyDecision> => ({ outcome: "allow" }));
		await build({ grantPolicy: policyOf(evaluate), verifier: verifierFor(null) }).handle(ctx());
		expect(evaluate).not.toHaveBeenCalled();
	});
});

describe("jwt-bearer grant — aud names the client's configured resource audience (#518)", () => {
	// The session and device grants mint `aud` as
	// `client.allowedAudiences?.[0] ?? client.clientId`; this grant minted the
	// client id unconditionally, so one public client got tokens for
	// `https://api.example` from `session` and for `mobile-app` from
	// jwt-bearer, and a resource server pinning its own identifier accepted
	// the first and rejected the second for the same user, client and scopes.
	// #521: typed, so drift between this fixture and `AuthenticatedClient`
	// fails to compile instead of hiding behind `as never`.
	const client = (over: Partial<AuthenticatedClient> = {}): Partial<GrantContext> => ({
		authenticatedClient: {
			clientId: "mobile-app",
			tokenEndpointAuthMethod: "none",
			allowedScopes: [],
			...over,
		},
	});
	const claimsOf = (result: { status: number } & Record<string, unknown>) =>
		"tokens" in result
			? decodeJwt((result.tokens as { access_token: string }).access_token)
			: expect.fail("expected tokens");

	it("mints aud as the client's first allowedAudiences entry, the way the session grant does", async () => {
		const { result } = await build({}).handle(
			ctx({}, client({ allowedAudiences: ["https://api.example", "https://other.example"] })),
		);
		expect(result.status).toBe(200);
		expect(claimsOf(result).aud).toBe("https://api.example");
	});

	it("keeps azp and client_id on the client when aud names the resource", async () => {
		// The audience moved; the party the token was issued to did not.
		const { result } = await build({}).handle(
			ctx({}, client({ allowedAudiences: ["https://api.example"] })),
		);
		const claims = claimsOf(result);
		expect(claims.azp).toBe("mobile-app");
		expect(claims.client_id).toBe("mobile-app");
	});

	it("falls back to the client id when the client configures no allowedAudiences", async () => {
		// Unchanged, and never null: the fallback `session` and the device
		// grant use, since the token is bound to an end user and meant for a
		// resource, not for the authorization server.
		expect(claimsOf((await build({}).handle(ctx({}, client({})))).result).aud).toBe("mobile-app");
		expect(
			claimsOf((await build({}).handle(ctx({}, client({ allowedAudiences: [] })))).result).aud,
		).toBe("mobile-app");
	});

	it("mints the issuer as aud without an authenticated client (#520)", async () => {
		// RFC 7523 §3 makes client authentication optional, and with no
		// registration there is no resource or client to name. The token still
		// has to name someone: RFC 9068 §2.2 makes `aud` REQUIRED on an
		// `at+jwt`, and a token without one is refused by any verifier that
		// pins its audience — including this stack's own. The issuer is the one
		// audience every deployment has, and what the WebAuthn grant already
		// mints in the same position.
		const { result } = await build({}).handle(ctx({}, { authenticatedClient: null }));
		expect(result.status).toBe(200);
		expect(claimsOf(result).aud).toBe("https://auth.example");
	});

	it("honours a policy audience within the client's allowedAudiences", async () => {
		// The ceiling the grant said it did not have. `allowedAudiences` is
		// it, as it is for client_credentials and refresh_token.
		const { result } = await build({
			grantPolicy: allow({ grantedAudience: ["https://other.example"] }),
		}).handle(
			ctx({}, client({ allowedAudiences: ["https://api.example", "https://other.example"] })),
		);
		expect(result.status).toBe(200);
		expect(claimsOf(result).aud).toBe("https://other.example");
	});

	it("refuses a policy audience outside the client's allowedAudiences", async () => {
		// A buggy or compromised policy must not mint a token that a resource
		// server the client was never registered for would accept.
		const { result } = await build({
			grantPolicy: allow({ grantedAudience: ["https://evil.example"] }),
		}).handle(ctx({}, client({ allowedAudiences: ["https://api.example"] })));
		expect(result.status).toBe(500);
		expect("error" in result && result.error).toBe("server_error");
		expect("errorDescription" in result && result.errorDescription).toMatch(/allowedAudiences/);
	});

	it("refuses a policy audience when no authenticated client supplies a ceiling", async () => {
		// The rule `resolveScope` already applies to scope: a value with
		// nothing to bound it is refused, not granted. Silently dropping it —
		// the previous behaviour — let a policy believe it had narrowed the
		// audience of a token that carries none.
		const { result } = await build({
			grantPolicy: allow({ grantedAudience: ["https://api.example"] }),
		}).handle(ctx({}, { authenticatedClient: null }));
		expect(result.status).toBe(500);
		expect("error" in result && result.error).toBe("server_error");
		expect("errorDescription" in result && result.errorDescription).toMatch(/allowedAudiences/);
	});

	it("treats an empty grantedAudience as no audience decision", async () => {
		const { result } = await build({ grantPolicy: allow({ grantedAudience: [] }) }).handle(
			ctx({}, client({ allowedAudiences: ["https://api.example"] })),
		);
		expect(result.status).toBe(200);
		expect(claimsOf(result).aud).toBe("https://api.example");
	});

	it("refuses an out-of-bounds entry in any position, not only the first (#521)", async () => {
		// The ceiling check runs over the whole array before the flatten to
		// `[0]`: a policy returning [allowed, rogue] is refused, not quietly
		// minted for the allowed one.
		const { result } = await build({
			grantPolicy: allow({ grantedAudience: ["https://api.example", "https://evil.example"] }),
		}).handle(ctx({}, client({ allowedAudiences: ["https://api.example"] })));
		expect(result.status).toBe(500);
		expect("error" in result && result.error).toBe("server_error");
		expect("errorDescription" in result && result.errorDescription).toContain(
			"https://evil.example",
		);
	});

	it("flattens two in-bounds entries to the first (#521)", async () => {
		const { result } = await build({
			grantPolicy: allow({ grantedAudience: ["https://other.example", "https://api.example"] }),
		}).handle(
			ctx({}, client({ allowedAudiences: ["https://api.example", "https://other.example"] })),
		);
		expect(result.status).toBe(200);
		expect(claimsOf(result).aud).toBe("https://other.example");
	});

	it("treats an empty grantedAudience as no decision without a client too (#521)", async () => {
		// An empty array is "no decision" before the no-client refusal is
		// reached; the boundary of that refusal is exactly a non-empty one.
		const { result } = await build({ grantPolicy: allow({ grantedAudience: [] }) }).handle(
			ctx({}, { authenticatedClient: null }),
		);
		expect(result.status).toBe(200);
		expect(claimsOf(result).aud).toBe("https://auth.example");
	});

	it("logs jwt_bearer_policy_audience_refused for the operator who wired the policy (#521)", async () => {
		// This file's convention (`jwt_bearer_email_not_verified`): a refusal
		// an operator caused logs, so the operator who wired the gate can see
		// why devices are being refused.
		const warn = vi.fn();
		const logger = { error: vi.fn(), warn, info: vi.fn(), debug: vi.fn() };
		await build({
			logger,
			grantPolicy: allow({ grantedAudience: ["https://evil.example"] }),
		}).handle(ctx({}, client({ allowedAudiences: ["https://api.example"] })));
		await build({
			logger,
			grantPolicy: allow({ grantedAudience: ["https://api.example"] }),
		}).handle(ctx({}, { authenticatedClient: null }));

		expect(warn).toHaveBeenCalledTimes(2);
		for (const call of warn.mock.calls) {
			expect(call[1]).toBe("jwt_bearer_policy_audience_refused");
			expect(call[0]).toMatchObject({ kind: "stub" });
		}
		expect(warn.mock.calls[0]?.[0]).toMatchObject({
			reason: expect.stringContaining("https://evil.example"),
		});
		expect(warn.mock.calls[1]?.[0]).toMatchObject({
			reason: expect.stringContaining("no authenticated client"),
		});
	});

	it("logs the refusal's reason sanitised and capped: a policy may echo the caller's resource", async () => {
		// `boundPolicyAudience` quotes what the policy returned, and the grant
		// forwards the caller's `resource` to the policy unchecked.
		const warn = vi.fn();
		const logger = { error: vi.fn(), warn, info: vi.fn(), debug: vi.fn() };
		const hostile = `https://evil.example\r\nFORGED\u0085\u2028\u202e${"r".repeat(10_000)}`;
		await build({
			logger,
			// The resource is read only under RFC 8707's flag.
			config: { ...config, oauth: { ...config.oauth, resourceIndicator: { enabled: true } } },
			grantPolicy: policyOf(
				async (request) =>
					({ outcome: "allow", grantedAudience: request.resource }) as GrantPolicyDecision,
			),
		}).handle(ctx({ resource: hostile }, client({ allowedAudiences: ["https://api.example"] })));

		expect(warn).toHaveBeenCalledTimes(1);
		const [line, event] = warn.mock.calls[0] as [{ reason: string }, string];
		expect(event).toBe("jwt_bearer_policy_audience_refused");
		expect({
			// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be logged.
			unsafe: /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/.test(
				line.reason,
			),
			within200: line.reason.length <= 200,
			quotes: line.reason.includes("https://evil.example??FORGED"),
		}).toEqual({ unsafe: false, within200: true, quotes: true });
	});

	describe("RFC 8707 resource (#522)", () => {
		// Every sibling minting at /token derives and enforces the audience
		// from `resource` under `oauth.resourceIndicator.enabled`; this grant
		// imported neither helper and silently ignored the parameter, so an
		// operator who enabled the flag found one grant exempt.
		const flagOn = {
			...config,
			oauth: { ...config.oauth, resourceIndicator: { enabled: true } },
		} as unknown as AppConfig;
		const registered = (over: Partial<AuthenticatedClient> = {}) =>
			client({ allowedAudiences: ["https://api.example", "https://other.example"], ...over });

		it("derives the audience from an allowed resource when no policy narrows one", async () => {
			const { result } = await build({ config: flagOn }).handle(
				ctx({ resource: "https://other.example" }, registered()),
			);
			expect(result.status).toBe(200);
			expect(claimsOf(result).aud).toBe("https://other.example");
		});

		it("accepts the client id as a resource — the same ceiling a policy audience is held to", async () => {
			const { result } = await build({ config: flagOn }).handle(
				ctx({ resource: "mobile-app" }, registered()),
			);
			expect(result.status).toBe(200);
			expect(claimsOf(result).aud).toBe("mobile-app");
		});

		it("answers invalid_target for a resource outside allowedAudiences ∪ {clientId}", async () => {
			const { result } = await build({ config: flagOn }).handle(
				ctx({ resource: "https://evil.example" }, registered()),
			);
			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_target");
			expect("errorDescription" in result && result.errorDescription).toContain(
				"https://evil.example",
			);
		});

		it("answers invalid_target for two distinct resources — one aud cannot represent both", async () => {
			const { result } = await build({ config: flagOn }).handle(
				ctx({ resource: ["https://api.example", "https://other.example"] }, registered()),
			);
			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_target");
		});

		it("honours a policy that narrows to the requested resource, refuses one that narrows elsewhere", async () => {
			const narrowed = await build({
				config: flagOn,
				grantPolicy: allow({ grantedAudience: ["https://other.example"] }),
			}).handle(ctx({ resource: "https://other.example" }, registered()));
			expect(narrowed.result.status).toBe(200);

			const elsewhere = await build({
				config: flagOn,
				grantPolicy: allow({ grantedAudience: ["https://api.example"] }),
			}).handle(ctx({ resource: "https://other.example" }, registered()));
			expect(elsewhere.result.status).toBe(400);
			expect("error" in elsewhere.result && elsewhere.result.error).toBe("invalid_target");
		});

		it("forwards resource to the policy under the flag, and nothing without it", async () => {
			const evaluate = vi.fn(async () => ({ outcome: "allow" }) as GrantPolicyDecision);
			await build({ config: flagOn, grantPolicy: policyOf(evaluate) }).handle(
				ctx({ resource: "https://other.example" }, registered()),
			);
			expect(evaluate.mock.calls[0]?.[0]).toMatchObject({ resource: ["https://other.example"] });

			evaluate.mockClear();
			await build({ grantPolicy: policyOf(evaluate) }).handle(
				ctx({ resource: "https://other.example" }, registered()),
			);
			expect(evaluate.mock.calls[0]?.[0]?.resource).toBeUndefined();
		});

		it("flag off: resource is ignored and the default audience stands", async () => {
			const { result } = await build({}).handle(
				ctx({ resource: "https://evil.example" }, registered()),
			);
			expect(result.status).toBe(200);
			expect(claimsOf(result).aud).toBe("https://api.example");
		});

		it("refuses a resource without an authenticated client — nothing bounds the derivation", async () => {
			// No registration means no `allowedAudiences ∪ {clientId}` to derive
			// within; the token would carry the issuer, which represents no
			// resource, and RFC 8707 §2 calls that `invalid_target`. Naming a
			// resource is not a registration.
			const { result } = await build({ config: flagOn }).handle(
				ctx({ resource: "https://api.example" }, { authenticatedClient: null }),
			);
			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_target");
		});
	});

	describe("the assertion issuer's terms (#525)", () => {
		// A registry entry may say which audiences a token minted from its
		// assertions may name. That list is a ceiling on the issued `aud`
		// whatever chose it, and — with no authenticated client — the source
		// the registration would otherwise be (the #520 remedy).
		const trusted = (audience: readonly string[]) =>
			verifierFor({ subjectHandle: "device:abc", issuer: "https://devices.example", audience });
		const flagOn = {
			...config,
			oauth: { ...config.oauth, resourceIndicator: { enabled: true } },
		} as unknown as AppConfig;

		it("hands the verifier the presenting client, or nothing for an unauthenticated presenter", async () => {
			const verify = vi.fn(async () => ({ subjectHandle: "device:abc" }));
			const verifier: AssertionVerifier = { kind: "spy", verify };
			await build({ verifier }).handle(ctx({}, client({})));
			expect(verify).toHaveBeenLastCalledWith("an-assertion", { clientId: "mobile-app" });
			await build({ verifier }).handle(ctx({}, { authenticatedClient: null }));
			expect(verify).toHaveBeenLastCalledWith("an-assertion", { clientId: undefined });
		});

		it("mints the issuer's first allowed audience for an unauthenticated presenter", async () => {
			const { result } = await build({
				verifier: trusted(["https://api.example", "https://other.example"]),
			}).handle(ctx({}, { authenticatedClient: null }));
			expect(result.status).toBe(200);
			expect(claimsOf(result).aud).toBe("https://api.example");
		});

		it("lets a policy narrow within the issuer's audiences when no client supplies a ceiling", async () => {
			const within = await build({
				verifier: trusted(["https://api.example", "https://other.example"]),
				grantPolicy: allow({ grantedAudience: ["https://other.example"] }),
			}).handle(ctx({}, { authenticatedClient: null }));
			expect(within.result.status).toBe(200);
			expect(claimsOf(within.result).aud).toBe("https://other.example");

			const outside = await build({
				verifier: trusted(["https://api.example"]),
				grantPolicy: allow({ grantedAudience: ["https://evil.example"] }),
			}).handle(ctx({}, { authenticatedClient: null }));
			expect(outside.result.status).toBe(500);
			expect("error" in outside.result && outside.result.error).toBe("server_error");
		});

		it("derives a requested resource within the issuer's audiences when no client supplies a ceiling", async () => {
			const { result } = await build({
				config: flagOn,
				verifier: trusted(["https://api.example", "https://other.example"]),
			}).handle(ctx({ resource: "https://other.example" }, { authenticatedClient: null }));
			expect(result.status).toBe(200);
			expect(claimsOf(result).aud).toBe("https://other.example");

			const outside = await build({
				config: flagOn,
				verifier: trusted(["https://api.example"]),
			}).handle(ctx({ resource: "https://evil.example" }, { authenticatedClient: null }));
			expect(outside.result.status).toBe(400);
			expect("error" in outside.result && outside.result.error).toBe("invalid_target");
		});

		it("bounds a client's audiences by the issuer's: the first the two share is minted", async () => {
			const { result } = await build({ verifier: trusted(["https://other.example"]) }).handle(
				ctx({}, client({ allowedAudiences: ["https://api.example", "https://other.example"] })),
			);
			expect(result.status).toBe(200);
			expect(claimsOf(result).aud).toBe("https://other.example");
		});

		it("falls back to the client id only when the issuer admits it", async () => {
			const { result } = await build({ verifier: trusted(["mobile-app"]) }).handle(
				ctx({}, client({ allowedAudiences: ["https://api.example"] })),
			);
			expect(result.status).toBe(200);
			expect(claimsOf(result).aud).toBe("mobile-app");
		});

		it("refuses, and logs, when the client and the issuer share no audience", async () => {
			// A registration mismatch between two things the operator configured:
			// the token would have to name an audience one side does not admit.
			const warn = vi.fn();
			const { result } = await build({
				logger: { error: vi.fn(), warn, info: vi.fn(), debug: vi.fn() },
				verifier: trusted(["https://other.example"]),
			}).handle(ctx({}, client({ allowedAudiences: ["https://api.example"] })));
			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_grant");
			expect(warn).toHaveBeenCalledWith(
				expect.objectContaining({ issuer: "https://devices.example", clientId: "mobile-app" }),
				"jwt_bearer_issuer_audience_mismatch",
			);
		});

		it("refuses a policy audience the client allows but the issuer does not", async () => {
			const { result } = await build({
				verifier: trusted(["https://other.example"]),
				grantPolicy: allow({ grantedAudience: ["https://api.example"] }),
			}).handle(
				ctx({}, client({ allowedAudiences: ["https://api.example", "https://other.example"] })),
			);
			expect(result.status).toBe(500);
			expect("error" in result && result.error).toBe("server_error");
		});

		it("issues no refresh token — the assertion is the refresh mechanism (ID-JAG §5, #526)", async () => {
			const { result } = await build({ verifier: trusted(["https://api.example"]) }).handle(
				ctx({}, client({ allowedAudiences: ["https://api.example"] })),
			);
			expect(result.status).toBe(200);
			expect("tokens" in result && result.tokens.refresh_token).toBeUndefined();
		});

		it("leaves the registration in charge when the issuer says nothing about audiences", async () => {
			const { result } = await build({
				verifier: verifierFor({ subjectHandle: "device:abc", issuer: "https://devices.example" }),
			}).handle(ctx({}, client({ allowedAudiences: ["https://api.example"] })));
			expect(result.status).toBe(200);
			expect(claimsOf(result).aud).toBe("https://api.example");
		});
	});
});

/*
 * auth.proxy#90 — the issued token never outlives the assertion.
 *
 * The grant stamped `exp` from `oauth.accessToken.expiresIn` with no reference
 * to the assertion at all, so a two-minute ID-JAG bought an hour-long access
 * token: the assertion's expiry, the one bound its issuing authority set,
 * stopped bounding anything the moment it was exchanged. Token exchange holds
 * the subject token to the same rule (its README, security note 16).
 */
describe("jwt-bearer grant — the token never outlives the assertion (auth.proxy#90)", () => {
	/** A whole epoch second, so the arithmetic below reads exactly. */
	const NOW = 1_800_000_000;
	const at = (seconds: number) => vi.setSystemTime(new Date(seconds * 1000));
	beforeEach(() => {
		vi.useFakeTimers({ toFake: ["Date"] });
		at(NOW);
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	const tokensOf = (result: GrantResult) => {
		if (!("tokens" in result)) return expect.fail(`expected tokens, got ${JSON.stringify(result)}`);
		return {
			expiresIn: result.tokens.expires_in,
			claims: decodeJwt(result.tokens.access_token),
		};
	};
	const unverified = async () =>
		(await build({ verifier: verifierFor(null) }).handle(ctx())).result;

	it("caps expires_in and exp at the assertion's remaining lifetime when it expires first", async () => {
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "device:abc", expiresAt: NOW + 120 }),
		}).handle(ctx());
		const { expiresIn, claims } = tokensOf(result);
		expect(expiresIn).toBe(120);
		expect(claims.exp).toBe(NOW + 120);
		// The response states the lifetime the token was minted with.
		expect((claims.exp as number) - (claims.iat as number)).toBe(expiresIn);
	});

	it("leaves the configured lifetime standing when the assertion outlives it", async () => {
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "device:abc", expiresAt: NOW + 3600 }),
		}).handle(ctx());
		const { expiresIn, claims } = tokensOf(result);
		expect(expiresIn).toBe(300);
		expect(claims.exp).toBe(NOW + 300);
	});

	it("leaves the configured lifetime standing when the verifier reports no expiry", async () => {
		// Omitting `expiresAt` asserts a credential with no expiry: there is no
		// lifetime for the cap to descend from.
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "device:abc" }),
		}).handle(ctx());
		expect(tokensOf(result).expiresIn).toBe(300);
	});

	it("rounds the remaining lifetime down, mid-second", async () => {
		at(NOW + 0.4);
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "device:abc", expiresAt: NOW + 120 }),
		}).handle(ctx());
		const { expiresIn, claims } = tokensOf(result);
		expect(expiresIn).toBe(119);
		expect(claims.exp as number).toBeLessThanOrEqual(NOW + 120);
	});

	it("refuses an assertion already past its exp — one a verifier admitted inside its clock tolerance", async () => {
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "device:abc", expiresAt: NOW - 5 }),
		}).handle(ctx());
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
		// The verifier folds expiry into its uniform refusal; so does the grant.
		expect(result).toEqual(await unverified());
	});

	it("refuses an assertion expiring within the current second rather than minting a token dead on arrival", async () => {
		for (const expiresAt of [NOW, NOW + 0.5]) {
			at(NOW);
			const { result } = await build({
				verifier: verifierFor({ subjectHandle: "device:abc", expiresAt }),
			}).handle(ctx());
			expect(result).toEqual(await unverified());
		}
		at(NOW + 0.4);
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "device:abc", expiresAt: NOW + 1 }),
		}).handle(ctx());
		expect(result).toEqual(await unverified());
	});

	it("takes the remaining lifetime at minting, not at verification", async () => {
		// A Store slow enough to outlast the assertion: it verified with thirty
		// seconds left and has none by the time a token would be signed.
		const { result } = await build({
			verifier: verifierFor({ subjectHandle: "device:abc", expiresAt: NOW + 30 }),
			userRepository: {
				authenticate: async () => null,
				authenticateByToken: async () => {
					at(NOW + 31);
					return { id: "u-1" };
				},
			} as never,
		}).handle(ctx());
		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_grant");
	});

	it("mints no exp past the assertion's when the clock moves between the cap and the mint", async () => {
		// A clock that ticks a whole second on every read: any two reads land in
		// different seconds. Capping against one read and stamping `exp` from
		// another mints `exp = later second + (assertion exp − earlier second)`,
		// past the assertion. Measuring both from one issuance instant cannot.
		let clockMs = NOW * 1000;
		const spy = vi.spyOn(Date, "now").mockImplementation(() => {
			const now = clockMs;
			clockMs += 1000;
			return now;
		});
		try {
			const expiresAt = NOW + 60;
			const { result } = await build({
				verifier: verifierFor({ subjectHandle: "device:abc", expiresAt }),
			}).handle(ctx());
			const { expiresIn, claims } = tokensOf(result);
			expect(claims.exp as number).toBeLessThanOrEqual(expiresAt);
			expect((claims.exp as number) - (claims.iat as number)).toBe(expiresIn);
		} finally {
			spy.mockRestore();
		}
	});

	it("refuses an expiresAt that is not a finite number — neither an expiry nor no expiry", async () => {
		// A custom verifier is typed, not checked. Arithmetic would coerce a
		// numeric string into an expiry and read Infinity as none; every one of
		// these is a verifier bug, and a bug here must not mint a token.
		const malformed = [
			String(NOW + 120),
			"later",
			null,
			Number.NaN,
			Number.POSITIVE_INFINITY,
			Number.NEGATIVE_INFINITY,
		] as unknown as number[];
		for (const expiresAt of malformed) {
			const info = vi.fn();
			const { result } = await build({
				logger: { error: vi.fn(), warn: vi.fn(), info, debug: vi.fn() },
				verifier: verifierFor({ subjectHandle: "device:abc", expiresAt }),
			}).handle(ctx());
			expect(result, `expiresAt: ${String(expiresAt)}`).toEqual(await unverified());
			expect(info).toHaveBeenCalledWith(expect.anything(), "jwt_bearer_assertion_expired");
		}
	});

	it("logs the expiry refusal for the operator — a skewed issuer clock shows up here", async () => {
		const info = vi.fn();
		await build({
			logger: { error: vi.fn(), warn: vi.fn(), info, debug: vi.fn() },
			verifier: verifierFor({
				subjectHandle: "device:abc",
				issuer: "https://devices.example",
				expiresAt: NOW - 5,
			}),
		}).handle(ctx());
		expect(info).toHaveBeenCalledWith(
			expect.objectContaining({ kind: "stub", issuer: "https://devices.example" }),
			"jwt_bearer_assertion_expired",
		);
	});

	it("caps a token minted from a real RFC 7523 assertion at its exp", async () => {
		const authority = generateKeyPairSync("ed25519");
		const verifier = createJwtAssertionVerifier({
			key: authority.publicKey,
			issuer: "https://devices.example",
			audience: "https://auth.example",
			algorithms: ["EdDSA"],
		});
		const assertion = await new SignJWT({ sub: "device:abc" })
			.setProtectedHeader({ alg: "EdDSA" })
			.setIssuer("https://devices.example")
			.setAudience("https://auth.example")
			.setExpirationTime(NOW + 45)
			.sign(authority.privateKey);
		const { result } = await build({ verifier }).handle(ctx({ assertion }));
		expect(tokensOf(result).expiresIn).toBe(45);
	});

	it("caps a token minted from a real ID-JAG at its exp — short-lived by design", async () => {
		const idp = generateKeyPairSync("ed25519");
		const verifier = createRegistryAssertionVerifier({
			registry: createMemoryAssertionIssuerRegistry([
				{
					issuer: "https://idp.example",
					keys: { type: "key", key: idp.publicKey },
					algorithms: ["EdDSA"],
					profile: "id-jag",
					allowedAudiences: ["https://api.example"],
				},
			]),
			audience: "https://auth.example",
			issuerIdentifier: "https://auth.example",
			replaySeenSet: createMemoryReplaySeenSet(),
		});
		const assertion = await new SignJWT({
			client_id: "mcp-client",
			jti: "jti-1",
			resource: "https://api.example",
		})
			.setProtectedHeader({ alg: "EdDSA", typ: "oauth-id-jag+jwt" })
			.setIssuer("https://idp.example")
			.setSubject("user-1")
			.setAudience("https://auth.example")
			.setIssuedAt(NOW - 30)
			.setExpirationTime(NOW + 90)
			.sign(idp.privateKey);
		const { result } = await build({ verifier }).handle(
			ctx(
				{ assertion },
				{
					authenticatedClient: {
						clientId: "mcp-client",
						tokenEndpointAuthMethod: "client_secret_basic",
						allowedScopes: [],
						allowedAudiences: ["https://api.example"],
					},
				},
			),
		);
		const { expiresIn, claims } = tokensOf(result);
		expect(expiresIn).toBe(90);
		expect(claims.exp).toBe(NOW + 90);
	});
});

describe("jwt-bearer grant — the lifetime it mints with, read when it is built", () => {
	it("is refused when it is built with a bad access-token lifetime, and no ID-JAG jti is spent", async () => {
		// Read when a request was answered, a hand-built lifetime the resolver
		// refuses failed only after the verifier had recorded the assertion's
		// jti: a 500, and an ID-JAG that can never be presented again.
		const idp = generateKeyPairSync("ed25519");
		const seen = createMemoryReplaySeenSet();
		const verifier = createRegistryAssertionVerifier({
			registry: createMemoryAssertionIssuerRegistry([
				{
					issuer: "https://idp.example",
					keys: { type: "key", key: idp.publicKey },
					algorithms: ["EdDSA"],
					profile: "id-jag",
				},
			]),
			audience: "https://auth.example",
			issuerIdentifier: "https://auth.example",
			replaySeenSet: seen,
		});
		const assertion = await new SignJWT({ client_id: "mcp-client", jti: "jti-lifetime" })
			.setProtectedHeader({ alg: "EdDSA", typ: "oauth-id-jag+jwt" })
			.setIssuer("https://idp.example")
			.setSubject("user-1")
			.setAudience("https://auth.example")
			.setIssuedAt()
			.setExpirationTime("5m")
			.sign(idp.privateKey);

		for (const accessToken of [{ expiresIn: 1.5 }, { expiresIn: 0 }, {}]) {
			let refused: unknown;
			let grant: ReturnType<typeof build> | undefined;
			try {
				grant = build({
					verifier,
					config: {
						oauth: { jwt: { issuer: "https://auth.example" }, accessToken },
					} as unknown as AppConfig,
				});
			} catch (err) {
				refused = err;
			}
			await grant
				?.handle(
					ctx(
						{ assertion },
						{
							authenticatedClient: {
								clientId: "mcp-client",
								tokenEndpointAuthMethod: "client_secret_basic",
								allowedScopes: [],
							},
						},
					),
				)
				.catch(() => undefined);

			expect(await seen.contains("jwt-bearer:id-jag:https://idp.example", "jti-lifetime")).toBe(
				false,
			);
			expect(refused, JSON.stringify(accessToken)).toBeInstanceOf(RangeError);
			expect((refused as Error).message).toMatch(/oauth\.accessToken/);
		}
	});
});

/*
 * #301 — enabling the grant without a verifier must fail at composition.
 *
 * The dangerous shape is a deployment that turns the grant on, wires nothing,
 * and gets a login endpoint whose possession check is absent. There is no
 * default verifier and there will not be one: the only possible default is one
 * that accepts things.
 */
describe("jwt-bearer grant — enabling it without a verifier (#301)", () => {
	const configWith = (enabled: boolean) =>
		({
			...(makeValidAppConfig() as unknown as Record<string, unknown>),
			oauth: {
				...(makeValidAppConfig() as unknown as { oauth: Record<string, unknown> }).oauth,
				grants: {
					"urn:ietf:params:oauth:grant-type:jwt-bearer": { enabled },
				},
			},
		}) as never;

	/** The contributed grant factories, or `{}` when the module contributes none. */
	const grantsOf = (enabled: boolean): Record<string, (d: unknown) => unknown> => {
		const mod = oauthAuthorizationModule({ config: configWith(enabled) });
		const contributed = mod.contributes?.grants;
		return (contributed ?? {}) as Record<string, (d: unknown) => unknown>;
	};

	/** Everything the grant needs except the one slot under test. */
	const depsWithout = (missing: "assertionVerifier" | "userRepository") => ({
		config: configWith(true),
		keyStore,
		...(missing === "assertionVerifier"
			? { userRepository: userRepoFor({ id: "u-1" }) }
			: { assertionVerifier: verifierFor({ subjectHandle: "d" }) }),
	});

	it("refuses to build the grant when the verifier is missing", () => {
		const factory = grantsOf(true)[JWT_BEARER_GRANT_TYPE];
		expect(factory).toBeDefined();
		expect(() => factory?.(depsWithout("assertionVerifier"))).toThrow(
			/no assertionVerifier is wired/,
		);
	});

	it("names both ways out — wire one, or disable the grant", () => {
		const factory = grantsOf(true)[JWT_BEARER_GRANT_TYPE];
		expect(factory).toBeDefined();
		let message = "did not throw";
		try {
			factory?.(depsWithout("assertionVerifier"));
		} catch (e) {
			message = (e as Error).message;
		}
		expect(message).toMatch(/createJwtAssertionVerifier/);
		expect(message).toMatch(/disable the grant/);
	});

	it("refuses to build the grant when the userRepository is missing", () => {
		// The grant resolves the verified handle through `authenticateByToken`;
		// without it the first request would fail at the call rather than at
		// boot, which is the wrong place to learn about a wiring gap.
		const factory = grantsOf(true)[JWT_BEARER_GRANT_TYPE];
		expect(() => factory?.(depsWithout("userRepository"))).toThrow(/no userRepository is wired/);
	});

	it("does not register the grant at all when it is not enabled", () => {
		// Secure-default opt-in: a deployment that says nothing gets nothing.
		expect(grantsOf(false)[JWT_BEARER_GRANT_TYPE]).toBeUndefined();
	});

	it("builds the grant when both slots are wired, handing the factory the narrowed values (#626)", () => {
		// The path past both refusals: the module lists `assertionVerifier` and
		// `userRepository` optional, the grant requires them, and the two checks
		// above are what narrow them — so this is where the wiring either passes
		// them on or drops them. Neither refusal fires and a handler for this
		// grant type comes back.
		const factory = grantsOf(true)[JWT_BEARER_GRANT_TYPE];
		expect(factory).toBeDefined();
		const handler = factory?.({
			config: configWith(true),
			keyStore,
			assertionVerifier: verifierFor({ subjectHandle: "d" }),
			userRepository: userRepoFor({ id: "u-1" }),
		}) as { handle: unknown; requiresExplicitGrantAllowlist?: boolean };
		expect(typeof handler.handle).toBe("function");
		// #326: the grant this module built is the one that refuses acquisition
		// by omission, so the values really reached `createJwtBearerGrant`.
		expect(handler.requiresExplicitGrantAllowlist).toBe(true);
	});
});
