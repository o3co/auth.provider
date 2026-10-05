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
 * RFC 8707 opt-in plumbing: flag-off / flag-on tests for the grant handlers
 * that carry `extractResourceParam` wiring. Token exchange is excluded.
 *
 * - refresh_token, client_credentials: the policy hook runs whatever the
 *   flag; flag-on forwards body.resource to it, flag-off forwards none.
 * - authorization_code: the policy is evaluated once, at /authorize, which
 *   locks scope; the token endpoint never invokes it, whatever the flag or
 *   body.resource, since re-evaluating there can mint over-scoped tokens
 *   (see ADR 2026-07-31-rfc8707-resource-audience-binding).
 */

import { createSecretKey } from "node:crypto";
import {
	type AuthenticatedClient,
	type ClientRepository,
	type CodeRepository,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
	type GrantPolicyHook,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import { SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { type AuthorizationGrantDeps, createAuthorizationGrant } from "#/grants/authorization.mjs";
import {
	type ClientCredentialsGrantDeps,
	createClientCredentialsGrant,
} from "#/grants/clientCredentials.mjs";
import { createRefreshTokenGrant, type RefreshTokenGrantDeps } from "#/grants/refreshToken.mjs";
import { OAUTH_ADMISSION_ACTIONS } from "./_helpers/admissionActions.mjs";
import { codeRecord } from "./_helpers/codeRecord.mjs";
import { grantSettingsFrom } from "./_helpers/grantSettings.mjs";

// ---------------------------------------------------------------------------
// Shared test setup
// ---------------------------------------------------------------------------

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);
const secretKey = createSecretKey(Buffer.from(SECRET));

const RP_URI = "https://rp.example/cb";
const CLIENT_ID = "client1";

const DEFAULT_AUTH_CLIENT: AuthenticatedClient = {
	clientId: CLIENT_ID,
	tokenEndpointAuthMethod: "client_secret_basic",
	allowedGrantTypes: ["client_credentials"],
	allowedScopes: ["read:res"],
	// An omitted scope is granted these, never the allowlist.
	defaultScopes: ["read:res"],
};

function makeStubPolicy(
	evaluate: GrantPolicyHook["evaluate"] = async () => ({ outcome: "allow" }),
): GrantPolicyHook {
	return { kind: "stub", evaluate };
}

// ---------------------------------------------------------------------------
// refresh_token setup helpers
// ---------------------------------------------------------------------------

async function makeRefreshToken(overrides: Record<string, unknown> = {}): Promise<string> {
	return new SignJWT({ sub: "u1", scope: "read write", ...overrides })
		.setProtectedHeader({ alg: "HS256", kid: "v0", typ: "rt+jwt" })
		.setIssuer("localhost")
		.setAudience(CLIENT_ID)
		.setExpirationTime("24h")
		.sign(secretKey);
}

function makeRefreshDeps(
	extra: Partial<GrantDependencies> = {},
	enableResourceIndicator?: boolean,
): RefreshTokenGrantDeps {
	const base = {
		oauth: {
			jwt: { secret: SECRET },
			accessToken: { expiresIn: 3600 },
			refreshToken: { expiresIn: 86400, unknownFamilyPolicy: "reject" },
			grants: {
				authorization_code: { enabled: true },
				refresh_token: { enabled: true },
			},
		},
	};
	if (enableResourceIndicator !== undefined) {
		(base.oauth as Record<string, unknown>).resourceIndicator = {
			enabled: enableResourceIndicator,
		};
	}
	return {
		sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		config: base as unknown as GrantDependencies["config"],
		...grantSettingsFrom(base),
		keyStore,
		...extra,
	};
}

// ---------------------------------------------------------------------------
// authorization_code setup helpers
// ---------------------------------------------------------------------------

const mockClientRepository: ClientRepository = {
	findById: vi.fn().mockResolvedValue(null),
	authenticate: vi.fn().mockResolvedValue(null),
};

function makeAuthzDeps(
	extra: Partial<GrantDependencies> = {},
	enableResourceIndicator?: boolean,
): AuthorizationGrantDeps {
	const base = {
		oauth: {
			jwt: { secret: "test-secret" },
			accessToken: { expiresIn: 3600 },
			refreshToken: { expiresIn: 86400 },
			grants: {
				authorization_code: { enabled: true },
				refresh_token: { enabled: true },
			},
		},
	};
	if (enableResourceIndicator !== undefined) {
		(base.oauth as Record<string, unknown>).resourceIndicator = {
			enabled: enableResourceIndicator,
		};
	}
	return {
		sessionRequirementResolver: resolverForTests([], { actions: OAUTH_ADMISSION_ACTIONS }),
		...grantSettingsFrom(base),
		keyStore: createSymmetricKeyStore("test-secret"),
		codeRepository: {
			consumeByCode: vi
				.fn()
				.mockResolvedValue(
					codeRecord({ code: "code-x", client_id: CLIENT_ID, redirect_uri: RP_URI }),
				),
			createCode: vi.fn(),
			findByCode: vi.fn(),
			removeByCode: vi.fn(),
		} as unknown as CodeRepository,
		clientRepository: mockClientRepository,
		...extra,
	};
}

function makeAuthzCtx(bodyOverrides: Record<string, unknown> = {}): GrantContext {
	return {
		body: {
			code: "abc",
			redirect_uri: RP_URI,
			...bodyOverrides,
		},
		session: { user: { id: "u1" } },
		issuer: "localhost",
		metadata: { ip: "127.0.0.1" },
		authenticatedClient: DEFAULT_AUTH_CLIENT,
	};
}

// ---------------------------------------------------------------------------
// client_credentials setup helpers
// ---------------------------------------------------------------------------

function makeCCDeps(
	extra: Partial<GrantDependencies> = {},
	enableResourceIndicator?: boolean,
): ClientCredentialsGrantDeps {
	const base = {
		oauth: {
			jwt: { issuer: "https://test.example" },
			accessToken: { expiresIn: 3600 },
			refreshToken: { expiresIn: 86400 },
		},
	};
	if (enableResourceIndicator !== undefined) {
		(base.oauth as Record<string, unknown>).resourceIndicator = {
			enabled: enableResourceIndicator,
		};
	}
	return {
		...grantSettingsFrom(base),
		keyStore,
		...extra,
	};
}

function makeCCCtx(bodyOverrides: Record<string, unknown> = {}): GrantContext {
	return {
		body: { grant_type: "client_credentials", ...bodyOverrides },
		session: {},
		issuer: "https://test.example",
		metadata: {},
		authenticatedClient: DEFAULT_AUTH_CLIENT,
	};
}

// ---------------------------------------------------------------------------
// Tests: flag off (resourceIndicator absent from config)
// ---------------------------------------------------------------------------

describe("RFC 8707 resource indicator — flag off (default, resourceIndicator absent)", () => {
	it("refresh_token: grantPolicy.evaluate sees resource: undefined when body.resource present", async () => {
		const token = await makeRefreshToken();
		let capturedResource: unknown = "NOT_CALLED";
		const policy = makeStubPolicy(async (req) => {
			capturedResource = req.resource;
			return { outcome: "allow" };
		});
		const deps = makeRefreshDeps({ grantPolicy: policy });
		const handler = createRefreshTokenGrant(deps);

		await handler.handle({
			body: { refresh_token: token, resource: "https://rs1" },
			session: {},
			issuer: "localhost",
			metadata: {},
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});

		// refresh_token calls grantPolicy.evaluate whatever the flag; flag-off,
		// resource is NOT forwarded (undefined).
		expect(capturedResource).toBeUndefined();
	});

	it("authorization_code: grantPolicy.evaluate is NOT called when flag is off", async () => {
		const seenPolicy = vi.fn().mockResolvedValue({ outcome: "allow" });
		const policy = makeStubPolicy(seenPolicy);
		const deps = makeAuthzDeps({ grantPolicy: policy });
		const handler = createAuthorizationGrant(deps);

		await handler.handle(makeAuthzCtx({ resource: "https://rs1" }));

		// Flag-off must NOT introduce a new policy invocation for authorization_code.
		expect(seenPolicy).not.toHaveBeenCalled();
	});

	it("client_credentials: grantPolicy.evaluate sees resource: undefined when flag is off", async () => {
		let capturedResource: unknown = "NOT_CALLED";
		const policy = makeStubPolicy(async (req) => {
			capturedResource = req.resource;
			return { outcome: "allow" };
		});
		const deps = makeCCDeps({ grantPolicy: policy });
		const handler = createClientCredentialsGrant(deps);

		await handler.handle(makeCCCtx({ resource: "https://rs1" }));

		// client_credentials calls grantPolicy.evaluate whatever the flag; flag-off,
		// resource is NOT forwarded (undefined).
		expect(capturedResource).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// Tests: flag off (resourceIndicator.enabled === false, explicit)
// ---------------------------------------------------------------------------

describe("RFC 8707 resource indicator — flag off (explicit false)", () => {
	it("refresh_token: grantPolicy.evaluate sees resource: undefined when body.resource present", async () => {
		const token = await makeRefreshToken();
		let capturedResource: unknown = "NOT_CALLED";
		const policy = makeStubPolicy(async (req) => {
			capturedResource = req.resource;
			return { outcome: "allow" };
		});
		const deps = makeRefreshDeps({ grantPolicy: policy }, false);
		const handler = createRefreshTokenGrant(deps);

		await handler.handle({
			body: { refresh_token: token, resource: "https://rs1" },
			session: {},
			issuer: "localhost",
			metadata: {},
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});

		// refresh_token: the policy call runs, resource NOT forwarded.
		expect(capturedResource).toBeUndefined();
	});

	it("authorization_code: grantPolicy.evaluate is NOT called when explicit false", async () => {
		const seenPolicy = vi.fn().mockResolvedValue({ outcome: "allow" });
		const policy = makeStubPolicy(seenPolicy);
		const deps = makeAuthzDeps({ grantPolicy: policy }, false);
		const handler = createAuthorizationGrant(deps);

		await handler.handle(makeAuthzCtx({ resource: "https://rs1" }));

		// Explicit false behaves as absent: no policy invocation.
		expect(seenPolicy).not.toHaveBeenCalled();
	});

	it("client_credentials: grantPolicy.evaluate sees resource: undefined when explicit false", async () => {
		let capturedResource: unknown = "NOT_CALLED";
		const policy = makeStubPolicy(async (req) => {
			capturedResource = req.resource;
			return { outcome: "allow" };
		});
		const deps = makeCCDeps({ grantPolicy: policy }, false);
		const handler = createClientCredentialsGrant(deps);

		await handler.handle(makeCCCtx({ resource: "https://rs1" }));

		// client_credentials: the policy call runs, resource NOT forwarded.
		expect(capturedResource).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// Tests: flag on (resourceIndicator.enabled === true)
// ---------------------------------------------------------------------------

describe("RFC 8707 resource indicator — flag on", () => {
	it("refresh_token: grantPolicy.evaluate sees resource: [string] when body.resource is string", async () => {
		const token = await makeRefreshToken();
		let capturedResource: unknown = "NOT_CALLED";
		const policy = makeStubPolicy(async (req) => {
			capturedResource = req.resource;
			return { outcome: "allow" };
		});
		const deps = makeRefreshDeps({ grantPolicy: policy }, true);
		const handler = createRefreshTokenGrant(deps);

		await handler.handle({
			body: { refresh_token: token, resource: "https://rs1" },
			session: {},
			issuer: "localhost",
			metadata: {},
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});

		expect(capturedResource).toEqual(["https://rs1"]);
	});

	it("refresh_token: grantPolicy.evaluate sees resource: array when body.resource is array", async () => {
		const token = await makeRefreshToken();
		let capturedResource: unknown = "NOT_CALLED";
		const policy = makeStubPolicy(async (req) => {
			capturedResource = req.resource;
			return { outcome: "allow" };
		});
		const deps = makeRefreshDeps({ grantPolicy: policy }, true);
		const handler = createRefreshTokenGrant(deps);

		await handler.handle({
			body: { refresh_token: token, resource: ["https://r1", "https://r2"] },
			session: {},
			issuer: "localhost",
			metadata: {},
			authenticatedClient: DEFAULT_AUTH_CLIENT,
		});

		expect(capturedResource).toEqual(["https://r1", "https://r2"]);
	});

	it("authorization_code: grantPolicy.evaluate is NOT called even when flag is on and body.resource is string", async () => {
		// Scope is already locked at /authorize, where the policy is evaluated
		// once; resource-aware narrowing here would break that.
		const seenPolicy = vi.fn().mockResolvedValue({ outcome: "allow" });
		const policy = makeStubPolicy(seenPolicy);
		const deps = makeAuthzDeps({ grantPolicy: policy }, true);
		const handler = createAuthorizationGrant(deps);

		await handler.handle(makeAuthzCtx({ resource: "https://rs1" }));

		expect(seenPolicy).not.toHaveBeenCalled();
	});

	it("authorization_code: grantPolicy.evaluate is NOT called even when flag is on and body.resource is array", async () => {
		const seenPolicy = vi.fn().mockResolvedValue({ outcome: "allow" });
		const policy = makeStubPolicy(seenPolicy);
		const deps = makeAuthzDeps({ grantPolicy: policy }, true);
		const handler = createAuthorizationGrant(deps);

		await handler.handle(makeAuthzCtx({ resource: ["https://r1", "https://r2"] }));

		expect(seenPolicy).not.toHaveBeenCalled();
	});

	it("client_credentials: grantPolicy.evaluate sees resource: [string] when body.resource is string", async () => {
		let capturedResource: unknown = "NOT_CALLED";
		const policy = makeStubPolicy(async (req) => {
			capturedResource = req.resource;
			return { outcome: "allow" };
		});
		const deps = makeCCDeps({ grantPolicy: policy }, true);
		const handler = createClientCredentialsGrant(deps);

		await handler.handle(makeCCCtx({ resource: "https://rs1" }));

		expect(capturedResource).toEqual(["https://rs1"]);
	});

	it("client_credentials: grantPolicy.evaluate sees resource: array when body.resource is array", async () => {
		let capturedResource: unknown = "NOT_CALLED";
		const policy = makeStubPolicy(async (req) => {
			capturedResource = req.resource;
			return { outcome: "allow" };
		});
		const deps = makeCCDeps({ grantPolicy: policy }, true);
		const handler = createClientCredentialsGrant(deps);

		await handler.handle(makeCCCtx({ resource: ["https://r1", "https://r2"] }));

		expect(capturedResource).toEqual(["https://r1", "https://r2"]);
	});

	it("authorization_code: grantPolicy.evaluate is NOT called even when flag is on and body has no resource", async () => {
		// authorization_code NEVER invokes grantPolicy.evaluate at the token
		// endpoint, whatever the flag or body.resource.
		const seenPolicy = vi.fn().mockResolvedValue({ outcome: "allow" });
		const policy = makeStubPolicy(seenPolicy);
		const deps = makeAuthzDeps({ grantPolicy: policy }, true);
		const handler = createAuthorizationGrant(deps);

		await handler.handle(makeAuthzCtx({})); // no body.resource

		expect(seenPolicy).not.toHaveBeenCalled();
	});

	it("client_credentials: grantPolicy.evaluate IS called with resource: undefined when flag is on but body has no resource", async () => {
		// Operator opted in → policy gate runs even without a resource param.
		const seenPolicy = vi.fn().mockResolvedValue({ outcome: "allow" });
		const policy = makeStubPolicy(seenPolicy);
		const deps = makeCCDeps({ grantPolicy: policy }, true);
		const handler = createClientCredentialsGrant(deps);

		await handler.handle(makeCCCtx({})); // no body.resource

		expect(seenPolicy).toHaveBeenCalledOnce();
		expect(seenPolicy.mock.calls[0][0].resource).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// Invariant: authorization_code NEVER invokes grantPolicy at token endpoint,
// across every flag state and body.resource shape.
// ---------------------------------------------------------------------------

describe("RFC 8707 authorization_code — token-endpoint policy invariant", () => {
	const flagStates: Array<{ label: string; enabled: boolean | undefined }> = [
		{ label: "flag absent", enabled: undefined },
		{ label: "flag explicit false", enabled: false },
		{ label: "flag explicit true", enabled: true },
	];

	const resourceStates: Array<{ label: string; resource?: string | string[] }> = [
		{ label: "no body.resource" },
		{ label: "body.resource string", resource: "https://rs1.example" },
		{ label: "body.resource array", resource: ["https://r1.example", "https://r2.example"] },
	];

	for (const flagState of flagStates) {
		for (const resourceState of resourceStates) {
			it(`grantPolicy.evaluate is NOT called: ${flagState.label}, ${resourceState.label}`, async () => {
				const seenPolicy = vi.fn().mockResolvedValue({ outcome: "allow" });
				const policy = makeStubPolicy(seenPolicy);
				const deps = makeAuthzDeps({ grantPolicy: policy }, flagState.enabled);
				const handler = createAuthorizationGrant(deps);

				const bodyOverrides: Record<string, unknown> = {};
				if (resourceState.resource !== undefined) {
					bodyOverrides.resource = resourceState.resource;
				}
				await handler.handle(makeAuthzCtx(bodyOverrides));

				expect(seenPolicy).not.toHaveBeenCalled();
			});
		}
	}
});
