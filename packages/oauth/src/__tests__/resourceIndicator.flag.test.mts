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
 * RFC 8707 opt-in plumbing — flag-off / flag-on tests for the 3 grant handlers
 * that carry `extractResourceParam` wiring (T18). Token-exchange is excluded
 * per spec §5.2.
 *
 * Each describe block has 3 grants × 3 tests = 9 tests, plus a regression note
 * confirming token-exchange is untouched.
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
import { SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createAuthorizationGrant } from "#/grants/authorization.mjs";
import { createClientCredentialsGrant } from "#/grants/clientCredentials.mjs";
import { createRefreshTokenGrant } from "#/grants/refreshToken.mjs";

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
): GrantDependencies {
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
		config: base as unknown as GrantDependencies["config"],
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
): GrantDependencies & { codeRepository: CodeRepository; clientRepository: ClientRepository } {
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
		config: base as unknown as GrantDependencies["config"],
		keyStore: createSymmetricKeyStore("test-secret"),
		codeRepository: {
			consumeByCode: vi.fn().mockResolvedValue({ client_id: CLIENT_ID, redirect_uri: RP_URI }),
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
): GrantDependencies {
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
		config: base as unknown as GrantDependencies["config"],
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

		// refresh_token has a pre-existing grantPolicy.evaluate call — it still
		// runs flag-off, but resource is NOT forwarded (undefined).
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

	it("client_credentials: grantPolicy.evaluate is NOT called when flag is off", async () => {
		const seenPolicy = vi.fn().mockResolvedValue({ outcome: "allow" });
		const policy = makeStubPolicy(seenPolicy);
		const deps = makeCCDeps({ grantPolicy: policy });
		const handler = createClientCredentialsGrant(deps);

		await handler.handle(makeCCCtx({ resource: "https://rs1" }));

		// Flag-off must NOT introduce a new policy invocation for client_credentials.
		expect(seenPolicy).not.toHaveBeenCalled();
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

		// refresh_token: pre-existing call still runs, resource NOT forwarded.
		expect(capturedResource).toBeUndefined();
	});

	it("authorization_code: grantPolicy.evaluate is NOT called when explicit false", async () => {
		const seenPolicy = vi.fn().mockResolvedValue({ outcome: "allow" });
		const policy = makeStubPolicy(seenPolicy);
		const deps = makeAuthzDeps({ grantPolicy: policy }, false);
		const handler = createAuthorizationGrant(deps);

		await handler.handle(makeAuthzCtx({ resource: "https://rs1" }));

		// Explicit false must preserve pre-existing semantics (no new invocation).
		expect(seenPolicy).not.toHaveBeenCalled();
	});

	it("client_credentials: grantPolicy.evaluate is NOT called when explicit false", async () => {
		const seenPolicy = vi.fn().mockResolvedValue({ outcome: "allow" });
		const policy = makeStubPolicy(seenPolicy);
		const deps = makeCCDeps({ grantPolicy: policy }, false);
		const handler = createClientCredentialsGrant(deps);

		await handler.handle(makeCCCtx({ resource: "https://rs1" }));

		// Explicit false must preserve pre-existing semantics (no new invocation).
		expect(seenPolicy).not.toHaveBeenCalled();
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

	it("authorization_code: grantPolicy.evaluate sees resource: [string] when body.resource is string", async () => {
		let capturedResource: unknown = "NOT_CALLED";
		const policy = makeStubPolicy(async (req) => {
			capturedResource = req.resource;
			return { outcome: "allow" };
		});
		const deps = makeAuthzDeps({ grantPolicy: policy }, true);
		const handler = createAuthorizationGrant(deps);

		await handler.handle(makeAuthzCtx({ resource: "https://rs1" }));

		expect(capturedResource).toEqual(["https://rs1"]);
	});

	it("authorization_code: grantPolicy.evaluate sees resource: array when body.resource is array", async () => {
		let capturedResource: unknown = "NOT_CALLED";
		const policy = makeStubPolicy(async (req) => {
			capturedResource = req.resource;
			return { outcome: "allow" };
		});
		const deps = makeAuthzDeps({ grantPolicy: policy }, true);
		const handler = createAuthorizationGrant(deps);

		await handler.handle(makeAuthzCtx({ resource: ["https://r1", "https://r2"] }));

		expect(capturedResource).toEqual(["https://r1", "https://r2"]);
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

	it("authorization_code: grantPolicy.evaluate IS called with resource: undefined when flag is on but body has no resource", async () => {
		// Operator opted in → policy gate runs even without a resource param.
		// This locks in the "feature on, client omitted resource" case so a future
		// refactor cannot accidentally treat it as flag-off.
		const seenPolicy = vi.fn().mockResolvedValue({ outcome: "allow" });
		const policy = makeStubPolicy(seenPolicy);
		const deps = makeAuthzDeps({ grantPolicy: policy }, true);
		const handler = createAuthorizationGrant(deps);

		await handler.handle(makeAuthzCtx({})); // no body.resource

		expect(seenPolicy).toHaveBeenCalledOnce();
		expect(seenPolicy.mock.calls[0][0].resource).toBeUndefined();
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
