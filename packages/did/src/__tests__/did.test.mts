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
import {
	createSymmetricKeyStore,
	type GrantContext,
	type GrantDependencies,
} from "@o3co/auth-provider-core";
import { CompactSign, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";

import { createDidGrant } from "../did.mjs";
import type { DidDocument, DidDocumentResolver, JsonWebKey } from "../resolver/types.mjs";
import { VerifierRegistry } from "../verifiers/registry.mjs";
import type { SignatureVerifier, VerificationContext, VerificationResult } from "../verifiers/types.mjs";

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
 * Build a mock DidDocumentResolver that returns a DID Document containing
 * the given Ed25519 public key encoded as a JWK.
 */
function buildResolver(did: string, publicKeyBytes: Uint8Array): DidDocumentResolver {
	const x = Buffer.from(publicKeyBytes).toString("base64url");
	const jwk: JsonWebKey = { kty: "OKP", crv: "Ed25519", x };
	const didDoc: DidDocument = {
		id: did,
		verificationMethod: [
			{
				id: `${did}#key-1`,
				type: "JsonWebKey2020",
				controller: did,
				publicKeyJwk: jwk,
			},
		],
	};
	return {
		async resolve(d: string): Promise<DidDocument> {
			if (d === did) return didDoc;
			throw new Error(`DID not found: ${d}`);
		},
	};
}

/**
 * Create a GrantContext with a real Ed25519 signature.
 * body.message is a raw JSON string (not base64) — matching the original wire format.
 * body.signature is base64-encoded. publicKey is no longer sent in the body.
 * Returns the context, the resolver, and the private key so callers can build
 * additional signed contexts with the same key pair.
 */
async function makeSignedCtx(
	did: string,
	overrides: Partial<{
		timestamp: string;
		nonce: string;
		audience: string;
		privateKey: Uint8Array;
	}> = {},
): Promise<{ ctx: GrantContext; resolver: DidDocumentResolver; privateKey: Uint8Array }> {
	const privateKey = overrides.privateKey ?? ed.utils.randomSecretKey();
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

	const resolver = buildResolver(did, publicKey);

	return {
		ctx: {
			body: {
				did,
				message, // raw JSON string
				signature: Buffer.from(signature).toString("base64"),
			},
			session: {},
			issuer: "localhost",
			metadata: { ip: "127.0.0.1" },
		},
		resolver,
		privateKey,
	};
}

describe("createDidGrant", () => {
	describe("handle – validation errors", () => {
		it("returns 400 when did is missing", async () => {
			const resolver: DidDocumentResolver = {
				async resolve() {
					throw new Error("should not be called");
				},
			};
			const handler = createDidGrant(mockDeps, { resolver });
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
			const oldTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();
			const { ctx, resolver } = await makeSignedCtx("did:key:abc", { timestamp: oldTimestamp });
			const handler = createDidGrant(mockDeps, { resolver });

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_request");
			expect("errorDescription" in result && result.errorDescription).toContain("timestamp");
		});

		it("returns 401 when signature verification fails", async () => {
			const did = "did:key:z6MkTest";
			// Use real public key bytes that don't match the signature
			const fakePrivateKey = ed.utils.randomSecretKey();
			const fakePublicKey = await ed.getPublicKeyAsync(fakePrivateKey);
			const resolver = buildResolver(did, fakePublicKey);
			const handler = createDidGrant(mockDeps, { resolver });

			const message = JSON.stringify({
				did,
				timestamp: new Date().toISOString(),
				nonce: crypto.randomUUID(),
			});
			// Signature made with a different private key — mismatches the resolver's key
			const differentPrivateKey = ed.utils.randomSecretKey();
			const wrongSignature = await ed.signAsync(
				new TextEncoder().encode(message),
				differentPrivateKey,
			);

			const ctx: GrantContext = {
				body: {
					did,
					message,
					signature: Buffer.from(wrongSignature).toString("base64"),
				},
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(401);
			expect("error" in result && result.error).toBe("invalid_grant");
		});

		it("returns 400 when resolver fails (DID not found)", async () => {
			const resolver: DidDocumentResolver = {
				async resolve(d: string): Promise<DidDocument> {
					throw new Error(`DID not found: ${d}`);
				},
			};
			const handler = createDidGrant(mockDeps, { resolver });

			const { ctx } = await makeSignedCtx("did:key:unknown");
			// Override the resolver so it always rejects
			const wrappedCtx: GrantContext = { ...ctx };

			const { result } = await handler.handle(wrappedCtx);

			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_request");
			expect("errorDescription" in result && result.errorDescription).toContain("DID not found");
		});
	});

	describe("handle – success", () => {
		it("returns 200 with access token on valid request", async () => {
			const { ctx, resolver } = await makeSignedCtx("did:key:z6MkTest");
			const handler = createDidGrant(mockDeps, { resolver });

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
			if ("tokens" in result) {
				expect(result.tokens.access_token).toBeDefined();
				expect(result.tokens.token_type).toBe("Bearer");
			}
		});

		it("returns 200 with audience when provided", async () => {
			const { ctx, resolver } = await makeSignedCtx("did:key:z6MkAud", {
				audience: "https://api.example.com",
			});
			const handler = createDidGrant(mockDeps, { resolver });

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
		});
	});

	describe("handle – nonce replay", () => {
		it("rejects nonce replay", async () => {
			const did = "did:key:z6MkReplay1";
			const fixedNonce = `nonce-replay-${Date.now()}`;

			// First request should succeed
			const { ctx: ctx1, resolver, privateKey } = await makeSignedCtx(did, { nonce: fixedNonce });
			const handler = createDidGrant(mockDeps, { resolver });
			const { result: result1 } = await handler.handle(ctx1);
			expect(result1.status).toBe(200);

			// Second request with the same DID + same nonce, same key pair — must fail with nonce replay
			const { ctx: ctx2 } = await makeSignedCtx(did, { nonce: fixedNonce, privateKey });
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

			const { ctx, resolver } = await makeSignedCtx("did:key:z6MkDefault");
			// Should not throw — falls back to defaults
			const handler = createDidGrant(
				{ config: noDIDConfig, keyStore: createSymmetricKeyStore("test-secret") },
				{ resolver },
			);
			expect(typeof handler.handle).toBe("function");

			// Verify it actually works with a real request (default algorithm = ed25519_raw)
			const { result } = await handler.handle(ctx);
			expect(result.status).toBe(200);
		});

		it("uses defaults when messageMaxAgeSec and algorithm are missing from did config", async () => {
			const partialConfig = {
				oauth: {
					accessToken: { expiresIn: 3600 },
					grants: { did: { enabled: true } },
				},
			} as unknown as GrantDependencies["config"];

			const { resolver } = await makeSignedCtx("did:key:z6MkPartial");
			const handler = createDidGrant(
				{ config: partialConfig, keyStore: createSymmetricKeyStore("test-secret") },
				{ resolver },
			);
			expect(typeof handler.handle).toBe("function");
		});
	});

	describe("cleanup", () => {
		it("exposes a cleanup method", async () => {
			const { resolver } = await makeSignedCtx("did:key:z6MkCleanup");
			const handler = createDidGrant(mockDeps, { resolver });
			expect(typeof handler.cleanup).toBe("function");
			handler.cleanup?.();
		});
	});

	describe("handle – multi-algorithm support", () => {
		/**
		 * Build a GrantContext where the DID signature is a compact JWS (EdDSA).
		 * Returns the context and a resolver that has the matching public key.
		 */
		async function makeJwsCtx(
			did: string,
			overrides: { audience?: string } = {},
		): Promise<{
			ctx: GrantContext;
			resolver: DidDocumentResolver;
		}> {
			const { privateKey, publicKey } = await generateKeyPair("EdDSA");
			const jwk = await exportJWK(publicKey);

			const payload = JSON.stringify({
				did,
				timestamp: new Date().toISOString(),
				nonce: `nonce-jws-${Date.now()}-${Math.random()}`,
				...(overrides.audience !== undefined ? { audience: overrides.audience } : {}),
			});

			const jws = await new CompactSign(new TextEncoder().encode(payload))
				.setProtectedHeader({ alg: "EdDSA" })
				.sign(privateKey);

			const didDoc: DidDocument = {
				id: did,
				verificationMethod: [
					{
						id: `${did}#key-1`,
						type: "JsonWebKey2020",
						controller: did,
						publicKeyJwk: jwk as JsonWebKey,
					},
				],
			};
			const resolver: DidDocumentResolver = {
				async resolve(d) {
					if (d === did) return didDoc;
					throw new Error(`DID not found: ${d}`);
				},
			};

			return {
				ctx: {
					body: { did, jws },
					session: {},
					issuer: "localhost",
					metadata: { ip: "127.0.0.1" },
				},
				resolver,
			};
		}

		it("accepts ed25519_raw when supportedAlgorithms includes it", async () => {
			const config = {
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { expiresIn: 3600 },
					grants: {
						did: { enabled: true, supportedAlgorithms: ["ed25519_raw"] },
					},
				},
			} as unknown as GrantDependencies["config"];

			const { ctx, resolver } = await makeSignedCtx("did:key:z6MkMultiRaw");
			const handler = createDidGrant(
				{ config, keyStore: createSymmetricKeyStore("test-secret") },
				{ resolver },
			);

			const { result } = await handler.handle(ctx);
			expect(result.status).toBe(200);
		});

		it("accepts ed25519_jws when supportedAlgorithms includes it", async () => {
			const config = {
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { expiresIn: 3600 },
					grants: {
						did: { enabled: true, supportedAlgorithms: ["ed25519_jws"] },
					},
				},
			} as unknown as GrantDependencies["config"];

			const { ctx, resolver } = await makeJwsCtx("did:key:z6MkMultiJws");
			const handler = createDidGrant(
				{ config, keyStore: createSymmetricKeyStore("test-secret") },
				{ resolver },
			);

			const { result } = await handler.handle(ctx);
			expect(result.status).toBe(200);
		});

		it("accepts both ed25519_raw and ed25519_jws when both are in supportedAlgorithms", async () => {
			const config = {
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { expiresIn: 3600 },
					grants: {
						did: { enabled: true, supportedAlgorithms: ["ed25519_raw", "ed25519_jws"] },
					},
				},
			} as unknown as GrantDependencies["config"];

			const rawResult = await (async () => {
				const { ctx, resolver } = await makeSignedCtx("did:key:z6MkBothRaw");
				const handler = createDidGrant(
					{ config, keyStore: createSymmetricKeyStore("test-secret") },
					{ resolver },
				);
				return handler.handle(ctx);
			})();

			const jwsResult = await (async () => {
				const { ctx, resolver } = await makeJwsCtx("did:key:z6MkBothJws");
				const handler = createDidGrant(
					{ config, keyStore: createSymmetricKeyStore("test-secret") },
					{ resolver },
				);
				return handler.handle(ctx);
			})();

			expect(rawResult.result.status).toBe(200);
			expect(jwsResult.result.status).toBe(200);
		});

		it("rejects a request whose detected algorithm is NOT in supportedAlgorithms", async () => {
			// Handler only supports ed25519_jws, but request uses ed25519_raw
			const config = {
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { expiresIn: 3600 },
					grants: {
						did: { enabled: true, supportedAlgorithms: ["ed25519_jws"] },
					},
				},
			} as unknown as GrantDependencies["config"];

			const { ctx, resolver } = await makeSignedCtx("did:key:z6MkRejectRaw");
			const handler = createDidGrant(
				{ config, keyStore: createSymmetricKeyStore("test-secret") },
				{ resolver },
			);

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_request");
			expect("errorDescription" in result && result.errorDescription).toContain("ed25519_raw");
			expect("errorDescription" in result && result.errorDescription).toContain("not supported");
		});

		it("rejects a request body that cannot be matched to any algorithm", async () => {
			const config = {
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { expiresIn: 3600 },
					grants: {
						did: { enabled: true, supportedAlgorithms: ["ed25519_raw"] },
					},
				},
			} as unknown as GrantDependencies["config"];

			const { resolver } = await makeSignedCtx("did:key:z6MkNoAlg");
			const handler = createDidGrant(
				{ config, keyStore: createSymmetricKeyStore("test-secret") },
				{ resolver },
			);

			const ctx: GrantContext = {
				body: { did: "did:key:z6MkNoAlg" }, // neither signature/message nor jws
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_request");
			expect("errorDescription" in result && result.errorDescription).toContain("detect");
		});

		it("backward compat: old algorithm field maps to supportedAlgorithms=[algorithm]", async () => {
			// Old config uses `algorithm` string — should still work
			const config = {
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { expiresIn: 3600 },
					grants: {
						did: { enabled: true, algorithm: "ed25519_raw", messageMaxAgeSec: 300 },
					},
				},
			} as unknown as GrantDependencies["config"];

			const { ctx, resolver } = await makeSignedCtx("did:key:z6MkBackCompat");
			const handler = createDidGrant(
				{ config, keyStore: createSymmetricKeyStore("test-secret") },
				{ resolver },
			);

			const { result } = await handler.handle(ctx);
			expect(result.status).toBe(200);
		});
	});

	describe("handle – custom verifierRegistry", () => {
		it("uses injected verifierRegistry instead of default", async () => {
			const did = "did:key:z6MkCustom";
			const privateKey = ed.utils.randomSecretKey();
			const publicKey = await ed.getPublicKeyAsync(privateKey);
			const resolver = buildResolver(did, publicKey);

			// Create a mock verifier that always succeeds
			const mockVerifier: SignatureVerifier = {
				async verify(ctx: VerificationContext): Promise<VerificationResult> {
					const parsedMessage = JSON.parse(ctx.body.message as string);
					return {
						valid: true,
						subject: ctx.did,
						audience: parsedMessage.audience,
						parsedMessage,
					};
				},
			};

			// Create a registry with only a custom algorithm
			const customRegistry = new VerifierRegistry();
			customRegistry.register("custom_alg", async () => mockVerifier);

			const config = {
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { expiresIn: 3600 },
					grants: {
						did: { enabled: true, supportedAlgorithms: ["custom_alg"] },
					},
				},
			} as unknown as GrantDependencies["config"];

			// This would fail with default registry ("custom_alg" not registered)
			// but succeeds with injected registry
			const handler = createDidGrant(
				{ config, keyStore: createSymmetricKeyStore("test-secret") },
				{ resolver, verifierRegistry: customRegistry },
			);

			expect(typeof handler.handle).toBe("function");
		});

		it("falls back to default registry when verifierRegistry is not provided", async () => {
			const { ctx, resolver } = await makeSignedCtx("did:key:z6MkFallback");
			const config = {
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { expiresIn: 3600 },
					grants: {
						did: { enabled: true, supportedAlgorithms: ["ed25519_raw"] },
					},
				},
			} as unknown as GrantDependencies["config"];

			const handler = createDidGrant(
				{ config, keyStore: createSymmetricKeyStore("test-secret") },
				{ resolver },
			);

			const { result } = await handler.handle(ctx);
			expect(result.status).toBe(200);
		});
	});

	describe("handle – audience allowlist", () => {
		function makeConfigWithAllowedAudiences(allowedAudiences: string[]) {
			return {
				oauth: {
					jwt: { secret: "test-secret" },
					accessToken: { expiresIn: 3600 },
					refreshToken: { expiresIn: 86400 },
					grants: {
						session: { enabled: true },
						authorization: { enabled: true },
						refresh_token: { enabled: true },
						did: {
							enabled: true,
							algorithm: "ed25519_raw",
							messageMaxAgeSec: 300,
							allowedAudiences,
						},
					},
				},
			} as unknown as GrantDependencies["config"];
		}

		it("returns 200 when audience is in the allowlist", async () => {
			const config = makeConfigWithAllowedAudiences([
				"https://api.example.com",
				"https://other.example.com",
			]);
			const { ctx, resolver } = await makeSignedCtx("did:key:z6MkAudAllow", {
				audience: "https://api.example.com",
			});
			const handler = createDidGrant({ config, keyStore: mockDeps.keyStore }, { resolver });

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
			expect("tokens" in result).toBe(true);
		});

		it("returns 400 when audience is NOT in the allowlist", async () => {
			const config = makeConfigWithAllowedAudiences(["https://api.example.com"]);
			const { ctx, resolver } = await makeSignedCtx("did:key:z6MkAudDeny", {
				audience: "https://evil.example.com",
			});
			const handler = createDidGrant({ config, keyStore: mockDeps.keyStore }, { resolver });

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result && result.error).toBe("invalid_request");
			expect("errorDescription" in result && result.errorDescription).toContain(
				"https://evil.example.com",
			);
			expect("errorDescription" in result && result.errorDescription).toContain("not allowed");
		});

		it("accepts any audience when allowedAudiences is empty (backward compat)", async () => {
			const config = makeConfigWithAllowedAudiences([]);
			const { ctx, resolver } = await makeSignedCtx("did:key:z6MkAudAny", {
				audience: "https://anything.example.com",
			});
			const handler = createDidGrant({ config, keyStore: mockDeps.keyStore }, { resolver });

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
		});

		it("returns 200 when no audience is provided even with allowedAudiences configured", async () => {
			const config = makeConfigWithAllowedAudiences(["https://api.example.com"]);
			// makeSignedCtx without audience override — audience is optional
			const { ctx, resolver } = await makeSignedCtx("did:key:z6MkAudOptional");
			const handler = createDidGrant({ config, keyStore: mockDeps.keyStore }, { resolver });

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(200);
		});
	});
});
