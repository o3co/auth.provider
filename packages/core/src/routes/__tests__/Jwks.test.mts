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

import type { Request, Response, Router } from "express";
import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { DEFAULT_JWKS_CACHE_MAX_AGE, resolveJwksCacheMaxAge } from "#/jwks/cache.mjs";
import { DEFAULT_JWKS_PATH, resolveJwksPath } from "#/jwks/path.mjs";
import { createAsymmetricKeyStore, createSymmetricKeyStore } from "#/keys/KeyStore.mjs";
import { createRouter } from "#/routes/Jwks.mjs";

type RouteHandler = (req: Request, res: Response) => unknown | Promise<unknown>;

function createMockExpress() {
	const routes: Record<string, RouteHandler> = {};
	const router = {
		get(path: string, handler: RouteHandler) {
			routes[path] = handler;
			return router;
		},
	};
	return { Router: () => router as unknown as Router, routes };
}

function createMockRes() {
	let statusCode = 200;
	let body: unknown;
	const headers: Record<string, string> = {};
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
		setHeader(name: string, value: string) {
			headers[name] = value;
			return this;
		},
		getStatusCode: () => statusCode,
		getBody: () => body,
		getHeader: (name: string) => headers[name],
	};
}

describe("JWKS path resolution", () => {
	it("defaults to the conventional well-known path", () => {
		expect(DEFAULT_JWKS_PATH).toBe("/.well-known/jwks.json");
		expect(resolveJwksPath({})).toBe(DEFAULT_JWKS_PATH);
		expect(resolveJwksPath({ oauth: { jwt: {} } })).toBe(DEFAULT_JWKS_PATH);
	});

	it("honors a configured oauth.jwt.jwksPath override", () => {
		expect(resolveJwksPath({ oauth: { jwt: { jwksPath: "/keys/jwks.json" } } })).toBe(
			"/keys/jwks.json",
		);
	});

	it("falls back to default for an empty/invalid configured value", () => {
		expect(resolveJwksPath({ oauth: { jwt: { jwksPath: "" } } })).toBe(DEFAULT_JWKS_PATH);
		expect(resolveJwksPath({ oauth: { jwt: { jwksPath: 123 } } })).toBe(DEFAULT_JWKS_PATH);
	});

	it("registers exactly the default path when no path is passed (single source of truth)", () => {
		const ks = createSymmetricKeyStore("test-secret");
		const express = createMockExpress();
		createRouter(express, ks);
		expect(Object.keys(express.routes)).toEqual([DEFAULT_JWKS_PATH]);
	});

	it("registers the explicit path when one is passed", () => {
		const ks = createSymmetricKeyStore("test-secret");
		const express = createMockExpress();
		createRouter(express, ks, { path: "/keys/jwks.json" });
		expect(Object.keys(express.routes)).toEqual(["/keys/jwks.json"]);
	});
});

describe("JWKS cache max-age resolution", () => {
	it("defaults to 300 seconds", () => {
		expect(DEFAULT_JWKS_CACHE_MAX_AGE).toBe(300);
		expect(resolveJwksCacheMaxAge({})).toBe(300);
		expect(resolveJwksCacheMaxAge({ oauth: { jwt: {} } })).toBe(300);
	});

	it("honors a configured oauth.jwt.jwksCacheMaxAge override (incl. 0)", () => {
		expect(resolveJwksCacheMaxAge({ oauth: { jwt: { jwksCacheMaxAge: 3600 } } })).toBe(3600);
		expect(resolveJwksCacheMaxAge({ oauth: { jwt: { jwksCacheMaxAge: 0 } } })).toBe(0);
	});

	it("falls back to default for negative / non-integer / non-number values", () => {
		expect(resolveJwksCacheMaxAge({ oauth: { jwt: { jwksCacheMaxAge: -1 } } })).toBe(300);
		expect(resolveJwksCacheMaxAge({ oauth: { jwt: { jwksCacheMaxAge: 1.5 } } })).toBe(300);
		expect(resolveJwksCacheMaxAge({ oauth: { jwt: { jwksCacheMaxAge: "60" } } })).toBe(300);
	});
});

describe("JWKS Cache-Control", () => {
	async function getHeaderFor(opts?: Parameters<typeof createRouter>[2]) {
		const ks = createSymmetricKeyStore("test-secret");
		const express = createMockExpress();
		createRouter(express, ks, opts);
		const res = createMockRes();
		await express.routes[opts?.path ?? "/.well-known/jwks.json"](
			{} as Request,
			res as unknown as Response,
		);
		return res.getHeader("Cache-Control");
	}

	it("sets public, max-age=300 by default", async () => {
		expect(await getHeaderFor()).toBe("public, max-age=300");
	});

	it("reflects a custom cacheMaxAgeSeconds", async () => {
		expect(await getHeaderFor({ cacheMaxAgeSeconds: 3600 })).toBe("public, max-age=3600");
	});

	it("sets the header on the HS256 empty-set response too", async () => {
		// createSymmetricKeyStore yields HS256 → empty keys; header must still be present.
		expect(await getHeaderFor({ cacheMaxAgeSeconds: 60 })).toBe("public, max-age=60");
	});

	it("sets the header on the asymmetric (ES256) success path", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
		const ks = await createAsymmetricKeyStore({
			algorithm: "ES256",
			kid: "k1",
			privateKeyPem: await exportPKCS8(privateKey),
			publicKeyPem: await exportSPKI(publicKey),
		});
		const express = createMockExpress();
		createRouter(express, ks);
		const res = createMockRes();
		await express.routes["/.well-known/jwks.json"]({} as Request, res as unknown as Response);
		expect(res.getHeader("Cache-Control")).toBe("public, max-age=300");
	});

	it("does NOT set Cache-Control when key export fails (no cacheable 5xx)", async () => {
		// A failing remote/KMS keystore must not produce a cacheable error: the
		// header is set only after getVerificationKeys()/exportJWK() succeed.
		const failingKeyStore = {
			algorithm: "ES256" as const,
			getVerificationKeys: async () => {
				throw new Error("kms unavailable");
			},
		} as unknown as Parameters<typeof createRouter>[1];
		const express = createMockExpress();
		createRouter(express, failingKeyStore);
		const res = createMockRes();
		await expect(
			express.routes["/.well-known/jwks.json"]({} as Request, res as unknown as Response),
		).rejects.toThrow("kms unavailable");
		expect(res.getHeader("Cache-Control")).toBeUndefined();
	});
});

describe("JWKS endpoint", () => {
	it("returns an empty JWK set for HS256 without exposing shared secrets", async () => {
		const ks = createSymmetricKeyStore("test-secret");
		const express = createMockExpress();
		createRouter(express, ks);
		const handler = express.routes["/.well-known/jwks.json"];
		const res = createMockRes();
		await handler({} as Request, res as unknown as Response);
		expect(res.getStatusCode()).toBe(200);
		expect(res.getBody()).toEqual({ keys: [] });
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
		createRouter(express, ks);
		const handler = express.routes["/.well-known/jwks.json"];
		const res = createMockRes();
		await handler({} as Request, res as unknown as Response);
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
		createRouter(express, ks);
		const res = createMockRes();
		await express.routes["/.well-known/jwks.json"]({} as Request, res as unknown as Response);
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
		createRouter(express, ks);
		const res = createMockRes();
		await express.routes["/.well-known/jwks.json"]({} as Request, res as unknown as Response);
		const body = res.getBody() as { keys: Array<Record<string, unknown>> };
		expect(body.keys).toHaveLength(1);
		expect(body.keys[0].kid).toBe("current");
	});
});
