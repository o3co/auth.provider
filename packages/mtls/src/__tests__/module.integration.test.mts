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
 * `mtlsModule` composed via `createApp`: disabled by default (no middleware,
 * no binding); enabled, a well-formed certificate header populates
 * `req.tokenBinding` (`kind: "mtls"`, `x5t#S256`) and a malformed one is
 * answered 400 `invalid_certificate`; boot refuses the configurations the
 * module cannot honour. Also the schema's secure defaults.
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
import { mtlsConfigSchema, mtlsModule } from "#/module.mjs";
import { shippedMtlsSection } from "./shippedSection.mjs";

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
/** Lowercase hex SHA-256 of the leaf's DER: what Envoy writes as XFCC `Hash=`. */
const LEAF_HASH_HEX = createHash("sha256").update(LEAF_DER).digest("hex");

interface MtlsTestConfig {
	enabled: boolean;
	source?: "header" | "tls-layer";
	certHeader?: string;
	certHeaderDialect?: "envoy" | "plain-pem";
	mode?: "self-signed" | "pki";
	trustedCas?: readonly string[];
	trustedProxies?: readonly string[];
}

const makeBoot = (mtls: MtlsTestConfig): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			core: {
				...makeValidCoreConfig().core,
				tokenBinding: { dispatchPolicy: "intent-explicit" },
			},
			mtls: {
				enabled: mtls.enabled,
				source: mtls.source ?? "header",
				certHeader: mtls.certHeader ?? "x-forwarded-client-cert",
				certHeaderDialect: mtls.certHeaderDialect ?? "envoy",
				mode: mtls.mode ?? "self-signed",
				trustedCas: mtls.trustedCas ?? [],
				// supertest dials the ephemeral listener over the loopback
				// interface, so the app sees `::ffff:127.0.0.1` / `::1`.
				trustedProxies: mtls.trustedProxies ?? ["loopback"],
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
			certHeaderDialect: "plain-pem",
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
			certHeaderDialect: "envoy",
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

		const xfcc = `By=spiffe://example;Hash=${LEAF_HASH_HEX};Cert=${encodeURIComponent(LEAF_PEM)}`;
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
			certHeaderDialect: "envoy",
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

		// XFCC without Cert= → the parser throws MtlsError("malformed_header").
		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", "By=spiffe://example;NoCertField=here")
			.send({});

		// The wire error is MtlsError.code, "invalid_certificate". The reason
		// (`malformed_header`) is internal-audit only and MUST NOT reach the
		// wire, as with DPoP's `invalid_dpop_proof`.
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_certificate");

		await handle.dispose();
	});

	it("when enabled + PKI mode + valid chain: extracts binding using envoy Chain= for intermediates", async () => {
		const boot = makeBoot({
			enabled: true,
			source: "header",
			certHeaderDialect: "envoy",
			mode: "pki",
			trustedCas: [ROOT_PEM],
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

	it("boot fails when source='header' and trustedProxies is empty", async () => {
		const boot = makeBoot({
			enabled: true,
			source: "header",
			trustedProxies: [],
		});

		await expect(
			createApp({
				modules: [mtlsModule],
				bootstrapComponents: boot,
			}),
		).rejects.toThrow(/trustedProxies/);
	});

	it("when enabled + header source + a peer outside trustedProxies: HTTP 400", async () => {
		// supertest connects over loopback; the allowlist names a different
		// address, so the forwarded certificate must be refused: reaching the
		// app directly must not assert an identity by setting the header.
		const boot = makeBoot({
			enabled: true,
			source: "header",
			certHeaderDialect: "plain-pem",
			mode: "self-signed",
			trustedProxies: ["10.0.0.7"],
		});
		const received: { tokenBinding?: unknown } = {};
		const handle = await createApp({
			modules: [mtlsModule, makeObserverModule(received)],
			bootstrapComponents: boot,
		});

		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app)
			.post("/oauth/token")
			.set("x-forwarded-client-cert", encodeURIComponent(LEAF_PEM))
			.send({});

		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_certificate");
		// No downgrade: the route must not have run with the binding stripped.
		expect(received.tokenBinding).toBeUndefined();

		await handle.dispose();
	});

	it("boot fails when mode='pki' and trustedCas is empty", async () => {
		const boot = makeBoot({
			enabled: true,
			mode: "pki",
			trustedCas: [],
		});

		await expect(
			createApp({
				modules: [mtlsModule],
				bootstrapComponents: boot,
			}),
		).rejects.toThrow(/trustedCas/);
	});

	it("boot fails when mode='pki' and source='tls-layer'", async () => {
		const boot = makeBoot({
			enabled: true,
			source: "tls-layer",
			mode: "pki",
			trustedCas: [ROOT_PEM],
		});

		const booting = createApp({
			modules: [mtlsModule],
			bootstrapComponents: boot,
		});
		await expect(booting).rejects.toThrow(/tls-layer/);
		// The refusal names the mode that reads the chain from the TLS session,
		// and no process label or issue number.
		await expect(booting).rejects.toThrow(/mode = "full-pki"/);
		await expect(booting).rejects.not.toThrow(/phase|#\d/i);
	});
});

// ---------------------------------------------------------------------------
// Config defaults
// ---------------------------------------------------------------------------

describe("the shipped mtls section — secure defaults", () => {
	it("takes the certificate from tls-layer, not the forwarded header", () => {
		// A "header" default would make merely enabling mTLS trust an
		// X-Forwarded-Client-Cert from whoever opened the connection. The
		// certificate comes from the transport unless an operator opts out AND
		// names the proxies allowed to speak for it.
		const parsed = mtlsConfigSchema.parse(shippedMtlsSection());
		expect(parsed?.source).toBe("tls-layer");
	});

	it("trusts no proxy: `trustedProxies` is an empty list", () => {
		const parsed = mtlsConfigSchema.parse(shippedMtlsSection());
		expect(parsed?.trustedProxies).toEqual([]);
	});

	it("keeps the module disabled", () => {
		const parsed = mtlsConfigSchema.parse(shippedMtlsSection());
		expect(parsed?.enabled).toBe(false);
	});

	it("fills nothing in the schema: an absent section stays absent, and the switch reads it as off", () => {
		expect(mtlsConfigSchema.parse(undefined)).toBeUndefined();
		expect(mtlsModule.section?.isEnabled?.(undefined)).toBe(false);
	});
});
