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
import * as ed from "@noble/ed25519";
import { createSymmetricKeyStore, type GrantContext, type GrantDependencies } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";

import { createDidGrant } from "../did.mjs";

const mockConfig = {
	oauth: {
		jwt: { secret: "test-secret" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {
			session: { enabled: true },
			authorization: { enabled: true },
			refresh_token: { enabled: true },
			did: { enabled: true, algorithm: "ed25519_raw", messageMaxAgeSec: 300 },
		},
	},
} as unknown as GrantDependencies["config"];

const mockDeps: GrantDependencies = {
	config: mockConfig,
	keyStore: createSymmetricKeyStore("test-secret"),
};

/**
 * Create a GrantContext with a real Ed25519 signature.
 * body.message is a raw JSON string (not base64) — matching the original wire format.
 * body.signature and body.publicKey are base64-encoded.
 */
async function makeSignedCtx(
	did: string,
	overrides: Partial<{ timestamp: string; nonce: string; audience: string }> = {},
): Promise<GrantContext> {
	const privateKey = ed.utils.randomSecretKey();
	const publicKey = await ed.getPublicKeyAsync(privateKey);

	const message = JSON.stringify({
		did,
		timestamp: overrides.timestamp ?? new Date().toISOString(),
		nonce: overrides.nonce ?? `nonce-${Date.now()}-${Math.random()}`,
		...(overrides.audience !== undefined ? { audience: overrides.audience } : {}),
	});

	// Sign the raw UTF-8 bytes of the JSON string
	const messageBytes = new TextEncoder().encode(message);
	const signature = await ed.signAsync(messageBytes, privateKey);

	return {
		body: {
			did,
			message, // raw JSON string
			signature: Buffer.from(signature).toString("base64"),
			publicKey: Buffer.from(publicKey).toString("base64"),
		},
		session: {},
		issuer: "localhost",
		metadata: { ip: "127.0.0.1" },
	};
}

describe("createDidGrant", () => {
	describe("handle – validation errors", () => {
		it("returns 400 when did is missing", async () => {
			const handler = createDidGrant(mockDeps);
			const ctx: GrantContext = {
				body: { signature: "sig", message: "msg" },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_request");
			expect("errorDescription" in result && result.errorDescription).toBe("did is required");
		});

		it("returns 400 when timestamp is expired", async () => {
			const handler = createDidGrant(mockDeps);
			const oldTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();
			const ctx = await makeSignedCtx("did:key:abc", { timestamp: oldTimestamp });

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_request");
			expect("errorDescription" in result && result.errorDescription).toContain("timestamp");
		});
	});

	describe("handle – success", () => {
		it("returns 200 with access token on valid request", async () => {
			const handler = createDidGrant(mockDeps);
			const ctx = await makeSignedCtx("did:key:z6MkTest");

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.access_token).toBeDefined();
				expect(result.tokens.token_type).toBe("Bearer");
			}
		});

		it("returns 200 with audience when provided", async () => {
			const handler = createDidGrant(mockDeps);
			const ctx = await makeSignedCtx("did:key:z6MkAud", { audience: "https://api.example.com" });

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
		});
	});

	describe("handle – nonce replay", () => {
		it("rejects nonce replay", async () => {
			const handler = createDidGrant(mockDeps);
			const fixedNonce = `nonce-replay-${Date.now()}`;

			// First request should succeed
			const ctx1 = await makeSignedCtx("did:key:z6MkReplay1", { nonce: fixedNonce });
			const { result: result1 } = await handler.handle(ctx1);
			expect(result1.status).toBe(200);

			// Second request with same nonce should fail
			const ctx2 = await makeSignedCtx("did:key:z6MkReplay2", { nonce: fixedNonce });
			const { result: result2 } = await handler.handle(ctx2);
			expect(result2.status).toBe(400);
			expect("error" in result2 && result2.error).toBe("invalid_request");
			expect("errorDescription" in result2 && result2.errorDescription).toContain("nonce");
		});
	});

	describe("config defaults", () => {
		it("uses default messageMaxAgeSec and algorithm when did config is absent", async () => {
			const noDIDConfig = {
				oauth: {
					accessToken: { expiresIn: 3600 },
					grants: {},
				},
			} as unknown as GrantDependencies["config"];

			// Should not throw — falls back to defaults
			const handler = createDidGrant({ config: noDIDConfig, keyStore: createSymmetricKeyStore("test-secret") });
			expect(typeof handler.handle).toBe("function");

			// Verify it actually works with a real request (default algorithm = ed25519_raw)
			const ctx = await makeSignedCtx("did:key:z6MkDefault");
			const { result } = await handler.handle(ctx);
			expect(result.status).toBe(200);
		});

		it("uses defaults when messageMaxAgeSec and algorithm are missing from did config", () => {
			const partialConfig = {
				oauth: {
					accessToken: { expiresIn: 3600 },
					grants: { did: { enabled: true } },
				},
			} as unknown as GrantDependencies["config"];

			const handler = createDidGrant({ config: partialConfig, keyStore: createSymmetricKeyStore("test-secret") });
			expect(typeof handler.handle).toBe("function");
		});
	});

	describe("cleanup", () => {
		it("exposes a cleanup method", () => {
			const handler = createDidGrant(mockDeps);
			expect(typeof handler.cleanup).toBe("function");
			handler.cleanup?.();
		});
	});
});
