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
 * mtls `discoveryMetadata` contribution.
 *
 * RFC 8705 §3.3 defines `tls_client_certificate_bound_access_tokens` as
 * authorization server metadata, defaulting to `false` when omitted. This
 * module binds access tokens to the client certificate (`cnf["x5t#S256"]`)
 * when enabled, so it — and only it — can answer the question truthfully.
 */

import {
	type BootstrapMap,
	createApp,
	createSymmetricKeyStore,
	defineModule,
	type OidcDiscoveryContribution,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { mtlsConfigSchema, mtlsModule } from "#/module.mjs";
import { shippedMtlsSection } from "./shippedSection.mjs";

/** The `mtls` section as boot hands it to the module: the shipped one under `overrides`, parsed with `mtlsConfigSchema`. */
function mtlsConfig(overrides: Record<string, unknown> = {}): unknown {
	return mtlsConfigSchema.parse(shippedMtlsSection(overrides));
}

async function contribution(section: unknown): Promise<OidcDiscoveryContribution> {
	const factory = mtlsModule.contributes?.discoveryMetadata?.[0];
	if (factory === undefined) throw new Error("mtlsModule contributes no discoveryMetadata");
	return await factory({ section } as never);
}

describe("mtlsModule — discoveryMetadata contribution", () => {
	it("advertises tls_client_certificate_bound_access_tokens when mTLS is enabled", async () => {
		const meta = await contribution(mtlsConfig({ enabled: true }));
		expect(meta.metadata?.tls_client_certificate_bound_access_tokens).toBe(true);
	});

	it("advertises the binding regardless of where the certificate comes from", async () => {
		// `source` is the TLS layer in reference.conf, and the header path sits behind a
		// trusted-proxy allowlist. Either way the ISSUED TOKEN carries
		// the same `cnf["x5t#S256"]`, and the RFC 8705 §3.3 flag describes the
		// token, not the transport the certificate arrived over.
		const meta = await contribution(
			mtlsConfig({ enabled: true, source: "header", trustedProxies: ["loopback"] }),
		);
		expect(meta.metadata?.tls_client_certificate_bound_access_tokens).toBe(true);
	});

	it("is switched off by its section when mTLS is disabled (the secure default), so nothing is contributed", () => {
		// RFC 8705 §3.3: an omitted flag already means `false`, and a disabled
		// module registers nothing, so the field is never contributed as `false`.
		expect(mtlsModule.section?.isEnabled?.(mtlsConfig())).toBe(false);
		expect(mtlsModule.section?.isEnabled?.(mtlsConfig({ enabled: true }))).toBe(true);
	});

	it("is switched off when the mtls section is absent entirely", () => {
		expect(mtlsModule.section?.isEnabled?.(mtlsConfigSchema.parse(undefined))).toBe(false);
	});

	it("never advertises the RFC 8705 §2 client-authentication methods", async () => {
		// This package implements token BINDING (§3), not mTLS client
		// authentication (§2). Adding `tls_client_auth` /
		// `self_signed_tls_client_auth` to `token_endpoint_auth_methods_supported`
		// would advertise a credential the token endpoint does not accept.
		const meta = await contribution(mtlsConfig({ enabled: true }));
		expect(meta.metadata).not.toHaveProperty("token_endpoint_auth_methods_supported");
	});

	it("stays an ancillary contributor — it never claims the provider root", async () => {
		expect((await contribution(mtlsConfig({ enabled: true }))).providerRoot).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// End-to-end: the contribution must survive core's aggregator and reach the
// served document. The unit tests above pin what the factory returns; only a
// boot proves that `discoveryMetadata` is a kind this module may contribute and
// that the empty-contribution shape does not break the aggregator.
// ---------------------------------------------------------------------------

/** The aggregator reads `id_token_signing_alg_values_supported` off this. */
const keyStoreModule = defineModule({
	name: "test:key-store",
	provides: {
		keyStore: () => createSymmetricKeyStore("test-secret-for-mtls-discovery!!!"),
	},
});

/**
 * Stands in for the authorization-server-owning module (`oauthEndpointsModule` lives
 * downstream of this package, so it cannot be imported here). Sets
 * `providerRoot` and supplies the OIDC-required fields
 * `buildDiscoveryDocument` insists on.
 */
const providerRootModule = defineModule({
	name: "test:provider-root",
	// `requires` (not just a sibling `provides`) so the planner materializes the
	// keyStore: the aggregator reads `id_token_signing_alg_values_supported` off
	// it, and refuses to build a document without one.
	requires: ["keyStore"],
	contributes: {
		discoveryMetadata: [
			() => ({
				providerRoot: true,
				endpoints: {
					authorization_endpoint: "/oauth/authorize",
					token_endpoint: "/oauth/token",
					jwks_uri: "/.well-known/jwks.json",
				},
				metadata: {
					response_types_supported: ["code"],
					subject_types_supported: ["public"],
				},
			}),
		],
	},
});

const bootWith = (mtls: Record<string, unknown>): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			mtls,
		} as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

describe("mtlsModule — discovery metadata in the served document", () => {
	it("serves tls_client_certificate_bound_access_tokens when enabled", async () => {
		const handle = await createApp({
			modules: [mtlsModule, keyStoreModule, providerRootModule],
			bootstrapComponents: bootWith({
				enabled: true,
				source: "tls-layer",
				certHeader: "x-forwarded-client-cert",
				certHeaderDialect: "envoy",
				trustedProxies: [],
				mode: "self-signed",
				trustedCas: [],
			}),
		});
		const app = express();
		app.use(handle.router);
		const { body } = await request(app).get("/.well-known/openid-configuration");
		expect(body.tls_client_certificate_bound_access_tokens).toBe(true);
		await handle.dispose();
	});

	it("serves a document without the field when disabled — and still boots", async () => {
		const handle = await createApp({
			modules: [mtlsModule, keyStoreModule, providerRootModule],
			bootstrapComponents: bootWith({
				enabled: false,
				source: "tls-layer",
				certHeader: "x-forwarded-client-cert",
				certHeaderDialect: "envoy",
				trustedProxies: [],
				mode: "self-signed",
				trustedCas: [],
			}),
		});
		const app = express();
		app.use(handle.router);
		const { status, body } = await request(app).get("/.well-known/openid-configuration");
		expect(status).toBe(200);
		expect(body).not.toHaveProperty("tls_client_certificate_bound_access_tokens");
		await handle.dispose();
	});
});
