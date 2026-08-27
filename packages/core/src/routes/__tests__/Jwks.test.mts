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

import { createSecretKey } from "node:crypto";
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

	it.each([
		"relative/jwks.json", // not absolute
		"//evil.example/jwks.json", // protocol-relative-ish
		"/../keys/jwks.json", // dot-segment traversal
		"/./keys/jwks.json", // single-dot segment
		"/keys/jwks.json?x=1", // query
		"/keys/jwks.json#frag", // fragment
		"/keys\\jwks.json", // backslash
		"/%2e%2e/keys", // percent-encoded traversal
		"/keys /jwks.json", // whitespace
		"/keys//jwks.json", // internal empty segment ("//")
		"/keys/jwks.json/", // trailing slash
	])("falls back to default for a malformed configured path (%j)", (jwksPath) => {
		// A path that would normalize to a different dereferenced route than the
		// one registered breaks the route ↔ jwks_uri single-source guarantee, so
		// the resolver rejects it (falls back to the safe default) rather than
		// publishing keys at — and advertising — a broken/ambiguous path.
		expect(resolveJwksPath({ oauth: { jwt: { jwksPath } } })).toBe(DEFAULT_JWKS_PATH);
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

describe("createRouter input validation (direct callers bypass the schema)", () => {
	const ks = createSymmetricKeyStore("test-secret");

	it("throws on a non-absolute path", () => {
		expect(() => createRouter(createMockExpress(), ks, { path: "keys/jwks.json" })).toThrow(
			/absolute path/,
		);
	});

	it.each(["/../keys/jwks.json", "//evil/jwks.json", "/keys?x=1", "/keys#f", "/keys\\x"])(
		"throws on a malformed path (%j) that would normalize away",
		(path) => {
			expect(() => createRouter(createMockExpress(), ks, { path })).toThrow(/absolute path/);
		},
	);

	it("throws on a negative or non-integer cacheMaxAgeSeconds", () => {
		expect(() => createRouter(createMockExpress(), ks, { cacheMaxAgeSeconds: -1 })).toThrow(
			/non-negative integer/,
		);
		expect(() => createRouter(createMockExpress(), ks, { cacheMaxAgeSeconds: 1.5 })).toThrow(
			/non-negative integer/,
		);
	});

	it("accepts a valid absolute path and a 0 max-age", () => {
		expect(() =>
			createRouter(createMockExpress(), ks, { path: "/keys/jwks.json", cacheMaxAgeSeconds: 0 }),
		).not.toThrow();
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
	async function makeEs256KeyStore() {
		const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
		return createAsymmetricKeyStore({
			algorithm: "ES256",
			kid: "cache-k1",
			privateKeyPem: await exportPKCS8(privateKey),
			publicKeyPem: await exportSPKI(publicKey),
		});
	}

	async function getHeaderFor(opts?: Parameters<typeof createRouter>[2]) {
		// #282: only a non-empty published key set is cacheable, so the
		// success-path header assertions run against an asymmetric keystore.
		const ks = await makeEs256KeyStore();
		const express = createMockExpress();
		createRouter(express, ks, opts);
		const res = createMockRes();
		await express.routes[opts?.path ?? "/.well-known/jwks.json"](
			{} as Request,
			res as unknown as Response,
		);
		return res.getHeader("Cache-Control");
	}

	async function getHs256HeaderFor(opts?: Parameters<typeof createRouter>[2]) {
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

	it("does NOT cache the HS256 refusal — it is a misconfiguration, not public data", async () => {
		// #282: HS256 no longer answers `{ keys: [] }` with a long public
		// max-age. A shared cache pinning that answer turns a fixable config
		// mistake into a stuck JWKS for the whole cache lifetime.
		expect(await getHs256HeaderFor({ cacheMaxAgeSeconds: 60 })).toBe("no-store");
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

describe("JWKS endpoint — never publishes an empty key set (#282)", () => {
	it("refuses to serve for HS256 instead of publishing `{ keys: [] }`", async () => {
		// Pre-#282 this answered 200 `{ keys: [] }`. A relying party cannot tell
		// that apart from "this issuer has rotated all its keys away", so it
		// caches the empty set and then fails every verification with an
		// unknown-kid error that points nowhere near the actual cause.
		const ks = createSymmetricKeyStore("test-secret");
		const express = createMockExpress();
		createRouter(express, ks);
		const handler = express.routes["/.well-known/jwks.json"];
		const res = createMockRes();
		await handler({} as Request, res as unknown as Response);
		expect(res.getStatusCode()).toBe(404);
		const body = res.getBody() as Record<string, unknown>;
		expect(body.keys).toBeUndefined();
		expect(body.error).toBe("jwks_not_published");
	});

	it("still never exposes the shared secret in the refusal body", async () => {
		const ks = createSymmetricKeyStore("test-secret-do-not-leak");
		const express = createMockExpress();
		createRouter(express, ks);
		const res = createMockRes();
		await express.routes["/.well-known/jwks.json"]({} as Request, res as unknown as Response);
		expect(JSON.stringify(res.getBody())).not.toContain("test-secret-do-not-leak");
	});

	it("names the algorithm and the fix in the HS256 refusal", async () => {
		const ks = createSymmetricKeyStore("test-secret");
		const express = createMockExpress();
		createRouter(express, ks);
		const res = createMockRes();
		await express.routes["/.well-known/jwks.json"]({} as Request, res as unknown as Response);
		const body = res.getBody() as { error_description?: string };
		expect(body.error_description).toMatch(/HS256/);
		expect(body.error_description).toMatch(/EdDSA|asymmetric/i);
	});

	it("refuses to serve when an asymmetric keystore yields zero publishable keys", async () => {
		// A KMS-backed keystore mid-rotation (or one whose only key is
		// unexportable) can return a set that filters down to nothing. That is
		// an outage, not a valid publication.
		const emptyKeyStore = {
			algorithm: "ES256" as const,
			getVerificationKeys: async () => [],
		} as unknown as Parameters<typeof createRouter>[1];
		const express = createMockExpress();
		createRouter(express, emptyKeyStore);
		const res = createMockRes();
		await express.routes["/.well-known/jwks.json"]({} as Request, res as unknown as Response);
		expect(res.getStatusCode()).toBe(503);
		const body = res.getBody() as Record<string, unknown>;
		expect(body.error).toBe("jwks_unavailable");
		expect(body.keys).toBeUndefined();
		expect(res.getHeader("Cache-Control")).toBe("no-store");
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

	it("strips private JWK members if a custom KeyStore adapter mistakenly returns a private key (defense in depth)", async () => {
		// The built-in stores only ever hold public key material, but `KeyStore`
		// is a public extension point. A third-party/KMS adapter that accidentally
		// hands the PRIVATE key as `publicKey` would otherwise export `d` (+ RSA
		// CRT params) straight into the JWKS response. The route must sanitize.
		const { privateKey } = await generateKeyPair("ES256", { extractable: true });
		const leakyKeyStore = {
			algorithm: "ES256" as const,
			getVerificationKeys: async () => [{ kid: "leaky", publicKey: privateKey }],
		} as unknown as Parameters<typeof createRouter>[1];
		const express = createMockExpress();
		createRouter(express, leakyKeyStore);
		const res = createMockRes();
		await express.routes["/.well-known/jwks.json"]({} as Request, res as unknown as Response);
		const body = res.getBody() as { keys: Array<Record<string, unknown>> };
		expect(body.keys).toHaveLength(1);
		expect(body.keys[0].kid).toBe("leaky");
		for (const priv of ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]) {
			expect(body.keys[0][priv]).toBeUndefined();
		}
	});

	it("excludes an oct (symmetric) key a custom adapter mistakenly returns (never publish `k`)", async () => {
		// exportJWK of a symmetric KeyObject yields `{ kty: "oct", k: <secret> }`.
		// A symmetric key has no public representation, so it must be dropped from
		// the JWKS entirely rather than sanitized to a keyless entry. #282: with
		// nothing left to publish the route now refuses rather than answering
		// 200 with an empty set — but the secret still never reaches the wire.
		const secret = createSecretKey(Buffer.from("super-secret-value-for-oct-jwks-test!!"));
		const octKeyStore = {
			algorithm: "ES256" as const,
			getVerificationKeys: async () => [{ kid: "oct-leak", publicKey: secret }],
		} as unknown as Parameters<typeof createRouter>[1];
		const express = createMockExpress();
		createRouter(express, octKeyStore);
		const res = createMockRes();
		await express.routes["/.well-known/jwks.json"]({} as Request, res as unknown as Response);
		expect(res.getStatusCode()).toBe(503);
		const serialized = JSON.stringify(res.getBody());
		expect(serialized).not.toContain("super-secret-value-for-oct-jwks-test");
		expect(serialized).not.toContain("oct-leak");
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
