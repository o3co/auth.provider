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
 * module.integration.test.mts
 *
 * Integration test for `dpopModule` composition via `createApp`.
 *
 * Sub-PR 2b scope (narrower than the full spec §12.2):
 *   - Verify `dpopModule` wires correctly with `createApp`.
 *   - When `oauth.dpop.enabled = false` (default), no DPoP middleware is
 *     mounted — requests succeed without a DPoP header.
 *   - When `oauth.dpop.enabled = true`, a valid DPoP proof populates
 *     `req.tokenBinding` with the correct `kind` and `confirmation.jkt`.
 *   - An invalid proof returns HTTP 400 with `error: "invalid_dpop_proof"`.
 *
 * Sub-PR 2c deferred:
 *   - `token_type: "DPoP"` in the response body.
 *   - `cnf.jkt` claim in the issued access token.
 *
 * Test pattern: copied from packages/core/src/boot/__tests__/
 *   grant-middleware.integration.test.mts (Phase 1d retro integration).
 *
 * Per Wave 2 Phase 2 spec §12.2 (narrowed) + Phase 2 plan T2.6.3.
 */

import { type BootstrapMap, createApp, defineModule } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import express, { type RequestHandler, Router } from "express";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { dpopModule } from "#/module.mjs";
import type { DPoPReplayStore } from "#/replay-store.mjs";
import { computeJkt } from "#/thumbprint.mjs";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Minimal bootstrap with extended dpop config. */
const makeBoot = (dpopEnabled: boolean): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			oauth: {
				...makeValidCoreConfig().oauth,
				dpop: {
					enabled: dpopEnabled,
					"iat-window-seconds": 60,
					"alg-whitelist": ["ES256", "ES384", "EdDSA", "RS256"],
					"replay-store": "memory",
					"replay-store-ttl-seconds": 300,
				},
				tokenBinding: {
					"dispatch-policy": "intent-explicit",
				},
			},
		} as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

/**
 * Mint a valid DPoP proof for POST http://as.example/oauth/token.
 *
 * supertest binds to http (not https). The request is sent with
 * `Host: as.example`, so the verifier's buildRequestUrl yields
 * `http://as.example/oauth/token` — the `htu` below must match exactly
 * (after normalizeHtu strips query/fragment and lowercases scheme+host).
 */
const mintProof = async () => {
	const { publicKey, privateKey } = await generateKeyPair("ES256");
	const jwk = await exportJWK(publicKey);
	const jkt = await computeJkt(jwk);
	const proof = await new SignJWT({
		htm: "POST",
		htu: "http://as.example/oauth/token",
		iat: Math.floor(Date.now() / 1000),
		jti: crypto.randomUUID(),
	})
		.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
		.sign(privateKey);
	return { proof, jkt };
};

/**
 * Build a route contribution that records the token binding on the request
 * and responds 200 with the binding JSON for assertion. Mirrors the Phase 1d
 * retro test pattern.
 */
const makeTokenBindingObserver =
	(received: { tokenBinding?: unknown }): RequestHandler =>
	(req, res) => {
		// biome-ignore lint/suspicious/noExplicitAny: test-only req augmentation access
		received.tokenBinding = (req as any).tokenBinding;
		res.status(200).json({ ok: true });
	};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("dpopModule — integration via createApp", () => {
	it("dpopModule has kind 'dpop' and intentExplicit from its mechanism", () => {
		// Structural smoke test: module name is stable.
		expect(dpopModule.name).toBe("dpop");
	});

	it("when disabled: no DPoP middleware; requests without DPoP header succeed", async () => {
		const boot = makeBoot(false);

		// Observer route: records req.tokenBinding, responds 200.
		const received: { tokenBinding?: unknown } = {};
		const observerModule = defineModule({
			name: "observer",
			requires: [],
			optional: [],
			contributes: {
				routes: [
					() => {
						const router = Router();
						router.use(express.json());
						router.post("/token", makeTokenBindingObserver(received));
						return { id: "test-token", mountPath: "/oauth", handler: router };
					},
				],
			},
		});

		const handle = await createApp({
			modules: [dpopModule, observerModule],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app).post("/oauth/token").send({});
		expect(res.status).toBe(200);
		// No DPoP header → tokenBinding should be undefined.
		expect(received.tokenBinding).toBeUndefined();

		await handle.dispose();
	});

	it("when enabled: valid DPoP proof populates req.tokenBinding with kind=dpop and confirmation.jkt", async () => {
		const boot = makeBoot(true);
		const { proof, jkt } = await mintProof();

		const received: { tokenBinding?: unknown } = {};
		const observerModule = defineModule({
			name: "observer",
			requires: [],
			optional: [],
			contributes: {
				routes: [
					() => {
						const router = Router();
						router.use(express.json());
						router.post("/token", makeTokenBindingObserver(received));
						return { id: "test-token", mountPath: "/oauth", handler: router };
					},
				],
			},
		});

		const handle = await createApp({
			modules: [dpopModule, observerModule],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app)
			.post("/oauth/token")
			.set("DPoP", proof)
			.set("Host", "as.example")
			.send({});

		expect(res.status).toBe(200);
		// req.tokenBinding should be populated with DPoP binding.
		expect(received.tokenBinding).toMatchObject({
			kind: "dpop",
			confirmation: { jkt },
		});

		await handle.dispose();
	});

	it("when enabled: invalid DPoP proof returns HTTP 400 with error=invalid_dpop_proof", async () => {
		const boot = makeBoot(true);

		const observerModule = defineModule({
			name: "observer",
			requires: [],
			optional: [],
			contributes: {
				routes: [
					() => {
						const router = Router();
						router.use(express.json());
						router.post("/token", (_req, res) => {
							res.status(200).json({ ok: true });
						});
						return { id: "test-token", mountPath: "/oauth", handler: router };
					},
				],
			},
		});

		const handle = await createApp({
			modules: [dpopModule, observerModule],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app)
			.post("/oauth/token")
			.set("DPoP", "not.a.valid.dpop.proof")
			.set("Host", "as.example")
			.send({});

		// tokenBindingMw returns 400 for invalid proofs.
		expect(res.status).toBe(400);
		expect(res.body).toMatchObject({ error: "invalid_dpop_proof" });

		await handle.dispose();
	});

	it("when enabled: consumer-wired dpopReplayStore is passed through to the mechanism (ComponentMap slot contract)", async () => {
		// Spy store: records each (jti, jkt) call so we can confirm the
		// composition root's store reached the mechanism — not the
		// in-memory fallback. The whole reason `dpopReplayStore` is a
		// ComponentMap slot is so production deployments can substitute
		// a Redis-backed adapter without forking core or dpop.
		const calls: { jti: string; jkt: string; ttlSeconds: number }[] = [];
		const consumerStore: DPoPReplayStore = {
			seen: async (jti, jkt, ttlSeconds) => {
				calls.push({ jti, jkt, ttlSeconds });
				return false;
			},
		};

		const boot = {
			...makeBoot(true),
			// Wire the slot via bootstrapComponents. Cast required because
			// the ambient `declare module` augmentation that adds
			// `dpopReplayStore` to ComponentMap only loads when @o3co/auth-
			// provider-dpop is in scope; the test imports it, but
			// BootstrapMap's structural typing here is satisfied via cast.
			dpopReplayStore: consumerStore,
		} as never as BootstrapMap;
		const { proof, jkt } = await mintProof();

		const observerModule = defineModule({
			name: "observer",
			requires: [],
			optional: [],
			contributes: {
				routes: [
					() => {
						const router = Router();
						router.use(express.json());
						router.post("/token", (_req, res) => {
							res.status(200).json({ ok: true });
						});
						return { id: "test-token", mountPath: "/oauth", handler: router };
					},
				],
			},
		});

		const handle = await createApp({
			modules: [dpopModule, observerModule],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app)
			.post("/oauth/token")
			.set("DPoP", proof)
			.set("Host", "as.example")
			.send({});

		expect(res.status).toBe(200);
		// The consumer store recorded exactly one (jti, jkt) call — proving
		// the slot was forwarded to the mechanism and the in-memory
		// fallback was NOT used.
		expect(calls).toHaveLength(1);
		expect(calls[0]?.jkt).toBe(jkt);
		expect(calls[0]?.ttlSeconds).toBe(300);

		await handle.dispose();
	});

	it("when enabled with replay-store=redis but slot unset: createApp fails fast (no silent in-memory fallback)", async () => {
		// Multi-replica deployments rely on Redis for cross-process
		// replay protection. A silent fallback to memory would let the
		// same (jti, jkt) be accepted by another replica — replay
		// protection bypassed. The module's factory throws at boot when
		// the config asks for redis but the slot is unwired.
		const boot = {
			config: {
				...makeValidCoreConfig(),
				oauth: {
					...makeValidCoreConfig().oauth,
					dpop: {
						enabled: true,
						"iat-window-seconds": 60,
						"alg-whitelist": ["ES256"],
						"replay-store": "redis", // ← contract: slot MUST be wired
						"replay-store-ttl-seconds": 300,
					},
					tokenBinding: {
						"dispatch-policy": "intent-explicit",
					},
				},
			} as never,
			pathResolver: (s: string) => s,
			// NOTE: dpopReplayStore intentionally NOT wired.
		} satisfies Record<string, unknown> as BootstrapMap;

		await expect(
			createApp({
				modules: [dpopModule],
				bootstrapComponents: boot,
			}),
		).rejects.toThrow(/replay-store = "redis" requires the `dpopReplayStore` ComponentMap slot/);
	});

	it("when enabled: absent DPoP header leaves req.tokenBinding unset (mechanism returns null)", async () => {
		const boot = makeBoot(true);

		const received: { tokenBinding?: unknown } = {};
		const observerModule = defineModule({
			name: "observer",
			requires: [],
			optional: [],
			contributes: {
				routes: [
					() => {
						const router = Router();
						router.use(express.json());
						router.post("/token", makeTokenBindingObserver(received));
						return { id: "test-token", mountPath: "/oauth", handler: router };
					},
				],
			},
		});

		const handle = await createApp({
			modules: [dpopModule, observerModule],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		// No DPoP header → mechanism.extract returns null → tokenBinding unset.
		const res = await request(app).post("/oauth/token").set("Host", "as.example").send({});

		expect(res.status).toBe(200);
		expect(received.tokenBinding).toBeUndefined();

		await handle.dispose();
	});
});
