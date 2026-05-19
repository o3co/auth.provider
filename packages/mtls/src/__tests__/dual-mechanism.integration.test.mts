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
 * dual-mechanism.integration.test.mts
 *
 * End-to-end integration test proving the cross-mechanism dispatch refactor
 * works for real consumers: when both `dpopModule` and `mtlsModule` are
 * installed and a request presents BOTH a DPoP proof AND a forwarded cert
 * header, the configured `DispatchPolicy` arbitrates across modules.
 *
 * Pins the resolution of the Phase 3 mTLS spec §11.4 known limitation:
 *
 *   Before:  each module independently mounted its own `tokenBindingMw`;
 *            the second one silently overwrote `req.tokenBinding`.
 *   After:   core composes ONE `tokenBindingMw` from both modules'
 *            `tokenBindingMechanisms` contributions; dispatch-policy applies
 *            across mechanisms.
 *
 * Per cross-mechanism dispatch refactor spec §6.4 at
 * `.claude/superpowers/specs/2026-05-19-wave-2-cross-mechanism-dispatch-refactor-spec.md`.
 */

import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { type BootstrapMap, createApp, defineModule } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import { dpopModule } from "@o3co/auth-provider-dpop";
import express, { type RequestHandler, Router } from "express";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { mtlsModule } from "#/module.mjs";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const LEAF_PEM = readFileSync(join(fixturesDir, "leaf.pem"), "utf8");

interface DualBootOpts {
	dispatchPolicy: "intent-explicit" | "strict-mutual-exclusion";
}

const makeBoot = ({ dispatchPolicy }: DualBootOpts): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			oauth: {
				...makeValidCoreConfig().oauth,
				tokenBinding: { "dispatch-policy": dispatchPolicy },
				dpop: {
					enabled: true,
					"iat-window-seconds": 60,
					"alg-whitelist": ["ES256", "ES384", "EdDSA", "RS256"],
					"replay-store": "memory",
					"replay-store-ttl-seconds": 300,
				},
				mtls: {
					enabled: true,
					source: "header",
					"cert-header": "x-forwarded-client-cert",
					"cert-header-dialect": "plain-pem",
					mode: "self-signed",
					"trusted-cas": [],
				},
			},
		} as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

/** Mint a real DPoP proof for `POST http://as.example/oauth/token`. */
const mintDpopProof = async () => {
	const { publicKey, privateKey } = await generateKeyPair("ES256");
	const jwk = await exportJWK(publicKey);
	const proof = await new SignJWT({
		htm: "POST",
		htu: "http://as.example/oauth/token",
		iat: Math.floor(Date.now() / 1000),
		jti: crypto.randomUUID(),
	})
		.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
		.sign(privateKey);
	return proof;
};

const makeObserverModule = (received: { binding?: unknown }) =>
	defineModule({
		name: "observer",
		requires: [],
		optional: [],
		contributes: {
			routes: [
				() => {
					const router = Router();
					router.use(express.json());
					router.post("/token", ((req, res) => {
						// biome-ignore lint/suspicious/noExplicitAny: test-only req augmentation access
						received.binding = (req as any).tokenBinding;
						res.status(200).json({ ok: true });
					}) as RequestHandler);
					return { id: "test-token", mountPath: "/oauth", handler: router };
				},
			],
		},
	});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("dpopModule + mtlsModule — cross-mechanism dispatch (refactor §6.4)", () => {
	it("intent-explicit: request presents BOTH DPoP and mTLS → DPoP (explicit) wins", async () => {
		const received: { binding?: unknown } = {};
		const handle = await createApp({
			// Register mtls FIRST to prove DispatchPolicy — not registration
			// order — picks the winner. Before this refactor, the second
			// middleware would have silently overwritten req.tokenBinding.
			modules: [mtlsModule, dpopModule, makeObserverModule(received)],
			bootstrapComponents: makeBoot({ dispatchPolicy: "intent-explicit" }),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const proof = await mintDpopProof();
		const res = await request(app)
			.post("/oauth/token")
			.set("DPoP", proof)
			.set("Host", "as.example")
			.set("x-forwarded-client-cert", encodeURIComponent(LEAF_PEM))
			.send({});

		expect(res.status).toBe(200);
		expect(received.binding).toMatchObject({ kind: "dpop" });

		await handle.dispose();
	});

	it("strict-mutual-exclusion: request presents BOTH → 400 invalid_request", async () => {
		const received: { binding?: unknown } = {};
		const handle = await createApp({
			modules: [dpopModule, mtlsModule, makeObserverModule(received)],
			bootstrapComponents: makeBoot({ dispatchPolicy: "strict-mutual-exclusion" }),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const proof = await mintDpopProof();
		const res = await request(app)
			.post("/oauth/token")
			.set("DPoP", proof)
			.set("Host", "as.example")
			.set("x-forwarded-client-cert", encodeURIComponent(LEAF_PEM))
			.send({});

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
		// The observer route MUST NOT have been reached.
		expect(received.binding).toBeUndefined();

		await handle.dispose();
	});

	it("only DPoP header → DPoP binding (mTLS is ambient absent)", async () => {
		const received: { binding?: unknown } = {};
		const handle = await createApp({
			modules: [dpopModule, mtlsModule, makeObserverModule(received)],
			bootstrapComponents: makeBoot({ dispatchPolicy: "intent-explicit" }),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const proof = await mintDpopProof();
		const res = await request(app)
			.post("/oauth/token")
			.set("DPoP", proof)
			.set("Host", "as.example")
			.send({});

		expect(res.status).toBe(200);
		expect(received.binding).toMatchObject({ kind: "dpop" });

		await handle.dispose();
	});

	it("only mTLS cert header → mTLS binding (DPoP absent)", async () => {
		const received: { binding?: unknown } = {};
		const handle = await createApp({
			modules: [dpopModule, mtlsModule, makeObserverModule(received)],
			bootstrapComponents: makeBoot({ dispatchPolicy: "intent-explicit" }),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const expectedThumbprint = require("node:crypto")
			.createHash("sha256")
			.update(new X509Certificate(LEAF_PEM).raw)
			.digest("base64url")
			.replace(/=+$/, "");

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", encodeURIComponent(LEAF_PEM))
			.send({});

		expect(res.status).toBe(200);
		expect(received.binding).toMatchObject({
			kind: "mtls",
			confirmation: { "x5t#S256": expectedThumbprint },
		});

		await handle.dispose();
	});

	it("neither presented → no binding (legacy unbound path preserved)", async () => {
		const received: { binding?: unknown } = {};
		const handle = await createApp({
			modules: [dpopModule, mtlsModule, makeObserverModule(received)],
			bootstrapComponents: makeBoot({ dispatchPolicy: "intent-explicit" }),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app).post("/oauth/token").send({});

		expect(res.status).toBe(200);
		expect(received.binding).toBeUndefined();

		await handle.dispose();
	});
});
