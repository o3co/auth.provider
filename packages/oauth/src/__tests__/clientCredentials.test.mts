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
	type AuthenticatedClient,
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
} from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { createClientCredentialsGrant } from "#/grants/clientCredentials.mjs";

const SECRET = "test-secret-at-least-32-chars!!";
const keyStore = createSymmetricKeyStore(SECRET);

const CLIENT_ID = "c-1";

const baseDeps: GrantDependencies = {
	config: {
		oauth: {
			jwt: { issuer: "https://test.example" },
			accessToken: { expiresIn: 3600 },
			refreshToken: { expiresIn: 86400 },
		},
	} as unknown as GrantDependencies["config"],
	keyStore,
};

function makeClient(overrides: Partial<AuthenticatedClient> = {}): AuthenticatedClient {
	return {
		clientId: CLIENT_ID,
		tokenEndpointAuthMethod: "client_secret_basic",
		allowedScopes: ["read:foo", "write:foo"],
		allowedAudiences: ["https://rs"],
		allowedGrantTypes: ["client_credentials"],
		...overrides,
	};
}

function makeCtx(
	client: AuthenticatedClient | null,
	body: Record<string, unknown> = { grant_type: "client_credentials" },
): GrantContext {
	return {
		body,
		session: {},
		issuer: "https://test.example",
		metadata: {},
		authenticatedClient: client,
	};
}

describe("createClientCredentialsGrant — gates", () => {
	it("returns 401 invalid_client when no authenticated client", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const { result } = await handler.handle(makeCtx(null));

		expect(result.status).toBe(401);
		expect("error" in result && result.error).toBe("invalid_client");
	});

	it("returns 400 invalid_client for public clients (tokenEndpointAuthMethod === 'none')", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ tokenEndpointAuthMethod: "none" });

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_client");
		expect("errorDescription" in result && result.errorDescription).toContain("confidential");
	});

	it("returns 400 unauthorized_client when allowedGrantTypes is absent (deny-by-absence)", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ allowedGrantTypes: undefined });

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("unauthorized_client");
	});

	it("returns 400 unauthorized_client when allowedGrantTypes is empty (deny on empty)", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ allowedGrantTypes: [] });

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("unauthorized_client");
	});

	it("returns 400 unauthorized_client when allowedGrantTypes excludes client_credentials", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ allowedGrantTypes: ["authorization_code"] });

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("unauthorized_client");
	});
});

describe("createClientCredentialsGrant — token issuance", () => {
	it("issues AT with sub=client_id and no refresh_token", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient();

		const { result } = await handler.handle(
			makeCtx(client, { grant_type: "client_credentials", scope: "read:foo" }),
		);

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		expect(result.tokens.access_token).toBeTruthy();
		// RFC 6749 §4.4.3: client_credentials does not issue a refresh_token.
		expect(result.tokens.refresh_token).toBeUndefined();

		const payload = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
		expect(payload.sub).toBe(CLIENT_ID);
		expect(payload.client_id).toBe(CLIENT_ID);
		expect(payload.azp).toBe(CLIENT_ID);
		expect(payload.scope).toBe("read:foo");
	});

	it("defaults scope to allowedScopes when scope is omitted", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ allowedScopes: ["s1", "s2"] });

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		const payload = decodeJwt(result.tokens.access_token) as Record<string, unknown>;
		expect(payload.scope).toBe("s1 s2");
	});

	it("returns 400 invalid_scope when requested scope is not in allowedScopes", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ allowedScopes: ["read:foo"] });

		const { result } = await handler.handle(
			makeCtx(client, { grant_type: "client_credentials", scope: "admin:all" }),
		);

		expect(result.status).toBe(400);
		expect("error" in result && result.error).toBe("invalid_scope");
		expect("errorDescription" in result && result.errorDescription).toContain("admin:all");
	});

	it("uses allowedAudiences[0] as the aud claim when present", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ allowedAudiences: ["https://api.example"] });

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("https://api.example");
	});

	it("falls back to issuer as aud when allowedAudiences is absent", async () => {
		const handler = createClientCredentialsGrant(baseDeps);
		const client = makeClient({ allowedAudiences: undefined });

		const { result } = await handler.handle(makeCtx(client));

		expect(result.status).toBe(200);
		if (!("tokens" in result)) throw new Error("expected tokens in result");
		const payload = decodeJwt(result.tokens.access_token);
		expect(payload.aud).toBe("https://test.example");
	});
});
