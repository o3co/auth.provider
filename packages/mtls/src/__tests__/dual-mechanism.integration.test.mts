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
 * With both `dpopModule` and `mtlsModule` installed, a request presenting BOTH
 * a DPoP proof AND a forwarded cert header is arbitrated across modules by the
 * configured `DispatchPolicy`: core composes ONE `tokenBindingMw` from both
 * modules' `tokenBindingMechanisms` contributions, so neither module's binding
 * silently overwrites the other's `req.tokenBinding`. See ADR
 * 2026-05-20-token-binding-first-class-abstraction.
 */

import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	type BootstrapMap,
	createApp,
	createMemoryReplaySeenSet,
	defineModule,
} from "@o3co/auth-provider-core";
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
					"replay-store-ttl-seconds": 300,
				},
				mtls: {
					enabled: true,
					source: "header",
					"cert-header": "x-forwarded-client-cert",
					"cert-header-dialect": "plain-pem",
					// The header source is only accepted from an
					// allowlisted peer. supertest dials the ephemeral listener
					// over loopback, which is what the app observes as the
					// forwarding hop here.
					"trusted-proxies": ["loopback"],
					mode: "self-signed",
					"trusted-cas": [],
				},
			},
		} as never,
		pathResolver: (s: string) => s,
		// DPoP records every proof it accepts in the seen-set.
		replaySeenSet: createMemoryReplaySeenSet(),
	}) satisfies Record<string, unknown> as BootstrapMap;

/**
 * The deployment's canonical issuer, as `makeValidCoreConfig` sets it. The
 * DPoP verifier builds the expected `htu` from this, not from the request's
 * protocol and `Host`, so the proof names it even though the requests below
 * send `Host: as.example` over plain http.
 */
const ISSUER_ORIGIN = "https://auth.test";

/** Mint a real DPoP proof for `POST <issuer origin>/oauth/token`. */
const mintDpopProof = async () => {
	const { publicKey, privateKey } = await generateKeyPair("ES256");
	const jwk = await exportJWK(publicKey);
	const proof = await new SignJWT({
		htm: "POST",
		htu: `${ISSUER_ORIGIN}/oauth/token`,
		iat: Math.floor(Date.now() / 1000),
		jti: crypto.randomUUID(),
	})
		.setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk })
		.sign(privateKey);
	return proof;
};

/**
 * Records what the downstream route saw.
 *
 * `reached` is tracked separately from `binding` on purpose: a route CAN be
 * entered with `tokenBinding === undefined` (the legitimate unbound path), so
 * `binding === undefined` alone never proves the request was stopped before
 * dispatch. Any assertion about rejection has to check `reached`.
 */
interface Received {
	binding?: unknown;
	reached?: boolean;
}

const makeObserverModule = (received: Received) =>
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
						received.reached = true;
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
		const received: Received = {};
		const handle = await createApp({
			// Register mtls FIRST to prove DispatchPolicy — not registration
			// order — picks the winner.
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
		const received: Received = {};
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
		// The observer route MUST NOT have been reached. Asserted via `reached`,
		// not `binding`: the route can legitimately run with no binding (see the
		// "neither presented" case), so an undefined binding would prove nothing.
		expect(received.reached).toBeUndefined();
		expect(received.binding).toBeUndefined();

		await handle.dispose();
	});

	it("only DPoP header → DPoP binding (mTLS is ambient absent)", async () => {
		const received: Received = {};
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
		const received: Received = {};
		const handle = await createApp({
			modules: [dpopModule, mtlsModule, makeObserverModule(received)],
			bootstrapComponents: makeBoot({ dispatchPolicy: "intent-explicit" }),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const expectedThumbprint = createHash("sha256")
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
		const received: Received = {};
		const handle = await createApp({
			modules: [dpopModule, mtlsModule, makeObserverModule(received)],
			bootstrapComponents: makeBoot({ dispatchPolicy: "intent-explicit" }),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app).post("/oauth/token").send({});

		expect(res.status).toBe(200);
		// Reached WITH no binding — the unbound path. This is also what makes
		// `reached` a trustworthy signal in the rejection cases: it proves the
		// observer actually records entry, so their `reached === undefined`
		// assertions cannot pass vacuously.
		expect(received.reached).toBe(true);
		expect(received.binding).toBeUndefined();

		await handle.dispose();
	});
});

// ---------------------------------------------------------------------------
// No-downgrade at the HTTP boundary
// ---------------------------------------------------------------------------

/**
 * Mixed validity: a **malformed DPoP proof** alongside a **valid mTLS cert**.
 * A request carrying invalid binding material is rejected outright, never
 * downgraded to the binding that did validate. So anyone who can inject a junk
 * `DPoP` header into a cert-bearing request kills it, and that is intended.
 *
 * "Rejects the request" and "falls back to mTLS" are both plausible readings
 * of the same code, and only one is a downgrade. Core's middleware tests pin
 * the rule with fake mechanisms; this pins it at the HTTP boundary with the
 * real modules, so a refactor that makes DPoP failures non-fatal (which would
 * look like a DoS fix) fails here.
 */
describe("dpopModule + mtlsModule — no downgrade on mixed validity (#199 R2)", () => {
	it("malformed DPoP + valid mTLS cert → 400, NOT a silent fallback to the mTLS binding", async () => {
		const received: Received = {};
		const handle = await createApp({
			modules: [dpopModule, mtlsModule, makeObserverModule(received)],
			bootstrapComponents: makeBoot({ dispatchPolicy: "intent-explicit" }),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app)
			.post("/oauth/token")
			// Not a JWT at all — fails at parse, before any claim check.
			.set("DPoP", "not-a-valid-dpop-proof")
			.set("Host", "as.example")
			.set("x-forwarded-client-cert", encodeURIComponent(LEAF_PEM))
			.send({});

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_dpop_proof");
		// The load-bearing assertion: the route was never entered, so nothing
		// was handed downstream in place of the failed DPoP binding. It has to
		// be `reached` — a route CAN run with `tokenBinding === undefined` on
		// the legitimate unbound path, so an undefined binding is consistent
		// with both "rejected" and "fell through unbound".
		expect(received.reached).toBeUndefined();
		expect(received.binding).toBeUndefined();

		await handle.dispose();
	});

	it("rejects on mechanism order too — mtlsModule registered first", async () => {
		// The middleware short-circuits on the first failing mechanism, so
		// swapping registration order exercises a different code path (early
		// return vs. reject-after-success) for the same observable outcome.
		// Without this, a refactor could make the outcome order-dependent and
		// only one arrangement would catch it.
		const received: Received = {};
		const handle = await createApp({
			modules: [mtlsModule, dpopModule, makeObserverModule(received)],
			bootstrapComponents: makeBoot({ dispatchPolicy: "intent-explicit" }),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app)
			.post("/oauth/token")
			.set("DPoP", "not-a-valid-dpop-proof")
			.set("Host", "as.example")
			.set("x-forwarded-client-cert", encodeURIComponent(LEAF_PEM))
			.send({});

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_dpop_proof");
		expect(received.reached).toBeUndefined();
		expect(received.binding).toBeUndefined();

		await handle.dispose();
	});

	it("malformed DPoP with no cert presented → same rejection, no unbound fallthrough", async () => {
		// Completes the shape: the rejection is a property of the invalid
		// material, not of there being a competing valid mechanism. A request
		// with junk binding material must not proceed as an unbound request
		// either.
		const received: Received = {};
		const handle = await createApp({
			modules: [dpopModule, mtlsModule, makeObserverModule(received)],
			bootstrapComponents: makeBoot({ dispatchPolicy: "intent-explicit" }),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app)
			.post("/oauth/token")
			.set("DPoP", "not-a-valid-dpop-proof")
			.set("Host", "as.example")
			.send({});

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_dpop_proof");
		expect(received.reached).toBeUndefined();
		expect(received.binding).toBeUndefined();

		await handle.dispose();
	});
});
