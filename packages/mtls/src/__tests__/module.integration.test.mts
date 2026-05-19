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
 * Integration test for `mtlsModule` composition via `createApp`. Mirrors the
 * pattern from `@o3co/auth-provider-dpop`'s module integration test.
 *
 * Sub-PR 3b scope (matches the spec §12.2 scope for module wiring):
 *   - `mtlsModule` wires correctly with `createApp`.
 *   - `oauth.mtls.enabled = false` (default) → no mTLS middleware mounted;
 *     requests without a cert header succeed and `req.tokenBinding` is
 *     unset.
 *   - `oauth.mtls.enabled = true` + a well-formed cert in the configured
 *     header → `req.tokenBinding` populated with `kind: "mtls"` and
 *     `confirmation.x5t#S256` matching the pre-computed thumbprint.
 *   - Malformed header → HTTP 400 with `error: "malformed_header"` (the
 *     MtlsError `reason` is forwarded as the OAuth error code).
 *   - Boot-time fail-loud: `mode = "pki"` + empty `trusted-cas` → throw.
 *   - Boot-time fail-loud: `mode = "pki"` + `source = "tls-layer"` → throw.
 *
 * Sub-PR 3c deferred: grant-side cnf emission + RT binding.
 *
 * Per Wave 2 Phase 3 spec §12.2 + §11.2.
 */

import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { type BootstrapMap, createApp, defineModule } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import express, { type RequestHandler, Router } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { mtlsModule } from "#/module.mjs";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

const LEAF_PEM = readFileSync(join(fixturesDir, "leaf.pem"), "utf8");
const INTERMEDIATE_PEM = readFileSync(join(fixturesDir, "intermediate.pem"), "utf8");
const ROOT_PEM = readFileSync(join(fixturesDir, "root.pem"), "utf8");
const LEAF_DER = new X509Certificate(LEAF_PEM).raw;
const EXPECTED_THUMBPRINT = createHash("sha256")
	.update(LEAF_DER)
	.digest("base64url")
	.replace(/=+$/, "");

interface MtlsTestConfig {
	enabled: boolean;
	source?: "header" | "tls-layer";
	"cert-header"?: string;
	"cert-header-dialect"?: "envoy" | "plain-pem";
	mode?: "self-signed" | "pki";
	"trusted-cas"?: readonly string[];
}

const makeBoot = (mtls: MtlsTestConfig): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			oauth: {
				...makeValidCoreConfig().oauth,
				mtls: {
					enabled: mtls.enabled,
					source: mtls.source ?? "header",
					"cert-header": mtls["cert-header"] ?? "x-forwarded-client-cert",
					"cert-header-dialect": mtls["cert-header-dialect"] ?? "envoy",
					mode: mtls.mode ?? "self-signed",
					"trusted-cas": mtls["trusted-cas"] ?? [],
				},
				tokenBinding: {
					"dispatch-policy": "intent-explicit",
				},
			},
		} as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

const makeTokenBindingObserver =
	(received: { tokenBinding?: unknown }): RequestHandler =>
	(req, res) => {
		// biome-ignore lint/suspicious/noExplicitAny: test-only req augmentation access
		received.tokenBinding = (req as any).tokenBinding;
		res.status(200).json({ ok: true });
	};

const makeObserverModule = (received: { tokenBinding?: unknown }) =>
	defineModule({
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("mtlsModule — integration via createApp", () => {
	it("module name is 'mtls' (structural smoke)", () => {
		expect(mtlsModule.name).toBe("mtls");
	});

	it("when disabled: no mTLS middleware mounted; cert-bearing requests pass without binding", async () => {
		const boot = makeBoot({ enabled: false });
		const received: { tokenBinding?: unknown } = {};
		const handle = await createApp({
			modules: [mtlsModule, makeObserverModule(received)],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		// PEM contains literal newlines which HTTP headers forbid; real
		// reverse-proxies URL-encode the value. parsePlainPemHeader auto-decodes.
		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", encodeURIComponent(LEAF_PEM))
			.send({});

		expect(res.status).toBe(200);
		// Even when a cert header is presented, disabled mTLS does not extract.
		expect(received.tokenBinding).toBeUndefined();

		await handle.dispose();
	});

	it("when enabled + plain-pem dialect: valid leaf cert populates req.tokenBinding.confirmation.x5t#S256", async () => {
		const boot = makeBoot({
			enabled: true,
			source: "header",
			"cert-header-dialect": "plain-pem",
			mode: "self-signed",
		});
		const received: { tokenBinding?: unknown } = {};
		const handle = await createApp({
			modules: [mtlsModule, makeObserverModule(received)],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		// URL-encode the PEM (HTTP headers forbid literal newlines); the
		// parsePlainPemHeader internal parser auto-decodes percent-encoded values.
		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", encodeURIComponent(LEAF_PEM))
			.send({});

		expect(res.status).toBe(200);
		expect(received.tokenBinding).toMatchObject({
			kind: "mtls",
			confirmation: { "x5t#S256": EXPECTED_THUMBPRINT },
		});

		await handle.dispose();
	});

	it("when enabled + envoy dialect: URL-encoded XFCC populates req.tokenBinding", async () => {
		const boot = makeBoot({
			enabled: true,
			source: "header",
			"cert-header-dialect": "envoy",
			mode: "self-signed",
		});
		const received: { tokenBinding?: unknown } = {};
		const handle = await createApp({
			modules: [mtlsModule, makeObserverModule(received)],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const xfcc = `By=spiffe://example;Hash=abc;Cert=${encodeURIComponent(LEAF_PEM)}`;
		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc)
			.send({});

		expect(res.status).toBe(200);
		expect(received.tokenBinding).toMatchObject({
			kind: "mtls",
			confirmation: { "x5t#S256": EXPECTED_THUMBPRINT },
		});

		await handle.dispose();
	});

	it("when enabled + malformed header: HTTP 400 with error=malformed_header", async () => {
		const boot = makeBoot({
			enabled: true,
			"cert-header-dialect": "envoy",
			mode: "self-signed",
		});
		const received: { tokenBinding?: unknown } = {};
		const handle = await createApp({
			modules: [mtlsModule, makeObserverModule(received)],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		// XFCC without Cert= → parser throws → MtlsError("malformed_header") →
		// tokenBindingMw forwards reason as the OAuth `error` field.
		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", "By=spiffe://example;NoCertField=here")
			.send({});

		// The wire-level OAuth error code is the MtlsError.code constant
		// "invalid_certificate" (spec §5.5). The granular MtlsReasonCode
		// (`malformed_header`) is an internal-audit field and MUST NOT
		// reach the wire — mirrors the DPoP `invalid_dpop_proof` discipline.
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_certificate");

		await handle.dispose();
	});

	it("when enabled + PKI mode + valid chain: extracts binding using envoy Chain= for intermediates", async () => {
		const boot = makeBoot({
			enabled: true,
			source: "header",
			"cert-header-dialect": "envoy",
			mode: "pki",
			"trusted-cas": [ROOT_PEM],
		});
		const received: { tokenBinding?: unknown } = {};
		const handle = await createApp({
			modules: [mtlsModule, makeObserverModule(received)],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const xfcc = `Cert=${encodeURIComponent(LEAF_PEM)};Chain=${encodeURIComponent(INTERMEDIATE_PEM)}`;
		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", xfcc)
			.send({});

		expect(res.status).toBe(200);
		expect(received.tokenBinding).toMatchObject({
			kind: "mtls",
			confirmation: { "x5t#S256": EXPECTED_THUMBPRINT },
		});

		await handle.dispose();
	});

	it("boot fails when mode='pki' and trusted-cas is empty (§11.2 check 1)", async () => {
		const boot = makeBoot({
			enabled: true,
			mode: "pki",
			"trusted-cas": [],
		});

		await expect(
			createApp({
				modules: [mtlsModule],
				bootstrapComponents: boot,
			}),
		).rejects.toThrow(/trusted-cas/);
	});

	it("boot fails when mode='pki' and source='tls-layer' (§11.2 check 2)", async () => {
		const boot = makeBoot({
			enabled: true,
			source: "tls-layer",
			mode: "pki",
			"trusted-cas": [ROOT_PEM],
		});

		await expect(
			createApp({
				modules: [mtlsModule],
				bootstrapComponents: boot,
			}),
		).rejects.toThrow(/tls-layer/);
	});
});
