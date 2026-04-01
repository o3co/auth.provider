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
import { describe, expect, it } from "vitest";

import { createDidGrant } from "../did.mjs";
import type { GrantContext, GrantDependencies } from "../types.mjs";

const mockConfig = {
	oauth: {
		jwt: { secret: "test-secret" },
		accessToken: { expiresIn: 3600 },
		refreshToken: { expiresIn: 86400 },
		grants: {
			session: { enabled: true },
			authorization: { enabled: true },
			refresh_token: { enabled: true },
			did: { enabled: true, messageMaxAgeSec: 300 },
		},
	},
} as unknown as GrantDependencies["config"];

const mockDeps: GrantDependencies = {
	config: mockConfig,
	clientRepository: {} as GrantDependencies["clientRepository"],
	codeRepository: {} as GrantDependencies["codeRepository"],
};

function makeValidMessage(did: string, overrides: Partial<{ did: string; timestamp: string; nonce: string; audience?: string }> = {}): string {
	return JSON.stringify({
		did,
		timestamp: new Date().toISOString(),
		nonce: `nonce-${Date.now()}-${Math.random()}`,
		...overrides,
	});
}

describe("createDidGrant", () => {
	describe("handle – validation errors", () => {
		it("returns 400 when did is missing", async () => {
			const handler = createDidGrant(mockDeps);
			const ctx: GrantContext = {
				body: { signature: "sig", message: "{}" },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			expect("error" in result).toBe(true);
			if ("error" in result) {
				expect(result.error).toBe("invalid_request");
			}
		});

		it("returns 400 when signature is missing", async () => {
			const handler = createDidGrant(mockDeps);
			const ctx: GrantContext = {
				body: { did: "did:key:abc", message: "{}" },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when message is missing", async () => {
			const handler = createDidGrant(mockDeps);
			const ctx: GrantContext = {
				body: { did: "did:key:abc", signature: "sig" },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when message is not valid JSON", async () => {
			const handler = createDidGrant(mockDeps);
			const ctx: GrantContext = {
				body: { did: "did:key:abc", signature: "sig", message: "not-json" },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			if ("error" in result) {
				expect(result.error).toBe("invalid_request");
			}
		});

		it("returns 400 when message.did does not match top-level did", async () => {
			const handler = createDidGrant(mockDeps);
			const message = makeValidMessage("did:key:different");
			const ctx: GrantContext = {
				body: { did: "did:key:abc", signature: "sig", message },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			if ("error" in result) {
				expect(result.error).toBe("invalid_request");
			}
		});

		it("returns 400 when message is missing nonce", async () => {
			const handler = createDidGrant(mockDeps);
			const message = JSON.stringify({
				did: "did:key:abc",
				timestamp: new Date().toISOString(),
				// nonce intentionally missing
			});
			const ctx: GrantContext = {
				body: { did: "did:key:abc", signature: "sig", message },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when message is missing timestamp", async () => {
			const handler = createDidGrant(mockDeps);
			const message = JSON.stringify({
				did: "did:key:abc",
				nonce: "some-nonce",
				// timestamp intentionally missing
			});
			const ctx: GrantContext = {
				body: { did: "did:key:abc", signature: "sig", message },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when timestamp is expired", async () => {
			const handler = createDidGrant(mockDeps);
			// 10 minutes ago — beyond the 300s max age
			const oldTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();
			const message = JSON.stringify({
				did: "did:key:abc",
				timestamp: oldTimestamp,
				nonce: "nonce-expired",
			});
			const ctx: GrantContext = {
				body: { did: "did:key:abc", signature: "sig", message },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			if ("error" in result) {
				expect(result.error).toBe("invalid_request");
			}
		});

		it("returns 400 when timestamp is invalid (NaN)", async () => {
			const handler = createDidGrant(mockDeps);
			const message = JSON.stringify({
				did: "did:key:abc",
				timestamp: "not-a-date",
				nonce: "nonce-nan",
			});
			const ctx: GrantContext = {
				body: { did: "did:key:abc", signature: "sig", message },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
		});

		it("returns 400 when publicKey is missing", async () => {
			const handler = createDidGrant(mockDeps);
			const did = "did:key:abc";
			const message = makeValidMessage(did);
			const ctx: GrantContext = {
				body: { did, signature: "c2ln", message },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			expect(result.status).toBe(400);
			if ("error" in result) {
				expect(result.error).toBe("invalid_request");
			}
		});

		it("returns 401 when signature verification fails", async () => {
			const handler = createDidGrant(mockDeps);
			const did = "did:key:abc";
			const message = makeValidMessage(did);
			// Random public key that won't match any valid signature
			const fakePublicKey = Buffer.alloc(32, 0x42).toString("base64");
			const fakeSignature = Buffer.alloc(64, 0x01).toString("base64");
			const ctx: GrantContext = {
				body: { did, signature: fakeSignature, message, publicKey: fakePublicKey },
				session: {},
				issuer: "localhost",
				metadata: { ip: "127.0.0.1" },
			};

			const { result } = await handler.handle(ctx);

			// signature verification fails → 401
			expect(result.status).toBe(401);
			if ("error" in result) {
				expect(result.error).toBe("invalid_grant");
			}
		});
	});

	describe("cleanup", () => {
		it("exposes a cleanup method", () => {
			const handler = createDidGrant(mockDeps);
			expect(typeof handler.cleanup).toBe("function");
			// Should not throw
			handler.cleanup?.();
		});
	});
});
