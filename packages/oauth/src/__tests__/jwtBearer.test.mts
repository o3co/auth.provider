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

import {
	type AppConfig,
	type AssertionVerifier,
	createSymmetricKeyStore,
	type GrantContext,
	type UserRepository,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { decodeJwt } from "jose";
import { describe, expect, it, vi } from "vitest";
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
}) =>
	createJwtBearerGrant({
		config,
		keyStore,
		assertionVerifier: opts.verifier ?? verifierFor({ subjectHandle: "device:abc" }),
		userRepository: opts.userRepository ?? userRepoFor({ id: "u-1" }),
		...(opts.logger ? { logger: opts.logger } : {}),
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
		expect(error).toHaveBeenCalledWith(
			expect.objectContaining({ err: expect.any(Error) }),
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

	it("rejects a non-string scope", async () => {
		const { result } = await build({}).handle(ctx({ scope: ["read"] }));
		expect("error" in result && result.error).toBe("invalid_request");
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
});
