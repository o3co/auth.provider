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
import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";
import { createAsymmetricKeyStore, createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import { createRouter } from "#/routes/Jwks.mjs";

function createMockExpress() {
	const routes: Record<string, Function> = {};
	const router = {
		get(path: string, handler: Function) {
			routes[path] = handler;
			return router;
		},
	};
	return { Router: () => router, routes };
}

function createMockRes() {
	let statusCode = 200;
	let body: unknown;
	return {
		status(code: number) {
			statusCode = code;
			return this;
		},
		json(data: unknown) {
			body = data;
			return this;
		},
		sendStatus(code: number) {
			statusCode = code;
			return this;
		},
		getStatusCode: () => statusCode,
		getBody: () => body,
	};
}

describe("JWKS endpoint", () => {
	it("returns 404 for HS256", () => {
		const ks = createSymmetricKeyStore("test-secret");
		const express = createMockExpress();
		createRouter(express as any, ks);
		const handler = express.routes["/.well-known/jwks.json"];
		const res = createMockRes();
		handler({}, res);
		expect(res.getStatusCode()).toBe(404);
	});

	it("returns JWK set for ES256", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
		const ks = await createAsymmetricKeyStore({
			algorithm: "ES256",
			kid: "test-key",
			privateKeyPem: await exportPKCS8(privateKey),
			publicKeyPem: await exportSPKI(publicKey),
		});
		const express = createMockExpress();
		createRouter(express as any, ks);
		const handler = express.routes["/.well-known/jwks.json"];
		const res = createMockRes();
		await handler({}, res);
		const body = res.getBody() as { keys: Array<Record<string, unknown>> };
		expect(body.keys).toHaveLength(1);
		expect(body.keys[0].kid).toBe("test-key");
		expect(body.keys[0].kty).toBe("EC");
		expect(body.keys[0].use).toBe("sig");
		expect(body.keys[0].alg).toBe("ES256");
		expect(body.keys[0].d).toBeUndefined(); // no private key
	});

	it("includes non-expired previous keys", async () => {
		const current = await generateKeyPair("ES256", { extractable: true });
		const prev = await generateKeyPair("ES256", { extractable: true });
		const ks = await createAsymmetricKeyStore({
			algorithm: "ES256",
			kid: "current",
			privateKeyPem: await exportPKCS8(current.privateKey),
			publicKeyPem: await exportSPKI(current.publicKey),
			previousKeys: [
				{
					kid: "old",
					publicKeyPem: await exportSPKI(prev.publicKey),
					expiresAt: new Date(Date.now() + 86400000),
				},
			],
		});
		const express = createMockExpress();
		createRouter(express as any, ks);
		const res = createMockRes();
		await express.routes["/.well-known/jwks.json"]({}, res);
		const body = res.getBody() as { keys: Array<Record<string, unknown>> };
		expect(body.keys).toHaveLength(2);
		expect(body.keys.map((k) => k.kid)).toContain("current");
		expect(body.keys.map((k) => k.kid)).toContain("old");
	});

	it("excludes expired previous keys", async () => {
		const current = await generateKeyPair("ES256", { extractable: true });
		const prev = await generateKeyPair("ES256", { extractable: true });
		const ks = await createAsymmetricKeyStore({
			algorithm: "ES256",
			kid: "current",
			privateKeyPem: await exportPKCS8(current.privateKey),
			publicKeyPem: await exportSPKI(current.publicKey),
			previousKeys: [
				{
					kid: "expired",
					publicKeyPem: await exportSPKI(prev.publicKey),
					expiresAt: new Date(Date.now() - 1000),
				},
			],
		});
		const express = createMockExpress();
		createRouter(express as any, ks);
		const res = createMockRes();
		await express.routes["/.well-known/jwks.json"]({}, res);
		const body = res.getBody() as { keys: Array<Record<string, unknown>> };
		expect(body.keys).toHaveLength(1);
		expect(body.keys[0].kid).toBe("current");
	});
});
