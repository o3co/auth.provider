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
 * mtls `discoveryMetadata` contribution (#283).
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
import { mtlsModule } from "#/module.mjs";

/** Build the mtls config slice as `mtlsConfigSchema` would leave it. */
function mtlsConfig(overrides: Record<string, unknown> = {}): unknown {
	return {
		oauth: {
			mtls: {
				enabled: false,
				source: "tls-layer",
				"cert-header": "x-forwarded-client-cert",
				"cert-header-dialect": "envoy",
				"trusted-proxies": [],
				mode: "self-signed",
				"trusted-cas": [],
				...overrides,
			},
		},
	};
}

function contribution(config: unknown): OidcDiscoveryContribution {
	const factory = mtlsModule.contributes?.discoveryMetadata?.[0];
	if (factory === undefined) throw new Error("mtlsModule contributes no discoveryMetadata");
	return factory({ config } as never);
}

describe("mtlsModule — discoveryMetadata contribution", () => {
	it("advertises tls_client_certificate_bound_access_tokens when mTLS is enabled", () => {
		const meta = contribution(mtlsConfig({ enabled: true }));
		expect(meta.metadata?.tls_client_certificate_bound_access_tokens).toBe(true);
	});

	it("advertises the binding regardless of where the certificate comes from", () => {
		// #280 made `source` default to the TLS layer and put a trusted-proxy
		// allowlist behind the header path. Either way the ISSUED TOKEN carries
		// the same `cnf["x5t#S256"]`, and the RFC 8705 §3.3 flag describes the
		// token, not the transport the certificate arrived over.
		const meta = contribution(
			mtlsConfig({ enabled: true, source: "header", "trusted-proxies": ["loopback"] }),
		);
		expect(meta.metadata?.tls_client_certificate_bound_access_tokens).toBe(true);
	});

	it("contributes nothing when mTLS is disabled (the secure default)", () => {
		// RFC 8705 §3.3: an omitted flag already means `false`. Contributing the
		// field as `false` would make a disabled module indistinguishable from an
		// uninstalled one only by accident; omission says the same thing and
		// cannot collide with another contributor.
		const meta = contribution(mtlsConfig());
		const all = { ...(meta.endpoints ?? {}), ...(meta.metadata ?? {}) };
		expect(all).not.toHaveProperty("tls_client_certificate_bound_access_tokens");
	});

	it("contributes nothing when the oauth.mtls slice is absent entirely", () => {
		const meta = contribution({ oauth: {} });
		const all = { ...(meta.endpoints ?? {}), ...(meta.metadata ?? {}) };
		expect(all).not.toHaveProperty("tls_client_certificate_bound_access_tokens");
	});

	it("never advertises the RFC 8705 §2 client-authentication methods", () => {
		// This package implements token BINDING (§3), not mTLS client
		// authentication (§2). Adding `tls_client_auth` /
		// `self_signed_tls_client_auth` to `token_endpoint_auth_methods_supported`
		// would advertise a credential the token endpoint does not accept.
		const meta = contribution(mtlsConfig({ enabled: true }));
		expect(meta.metadata).not.toHaveProperty("token_endpoint_auth_methods_supported");
	});

	it("stays an ancillary contributor — it never claims the provider root", () => {
		expect(contribution(mtlsConfig({ enabled: true })).providerRoot).toBeUndefined();
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
 * Stands in for the authorization-server-owning module (`oauthModule` lives
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
			oauth: { ...makeValidCoreConfig().oauth, mtls },
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
				"cert-header": "x-forwarded-client-cert",
				"cert-header-dialect": "envoy",
				"trusted-proxies": [],
				mode: "self-signed",
				"trusted-cas": [],
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
				"cert-header": "x-forwarded-client-cert",
				"cert-header-dialect": "envoy",
				"trusted-proxies": [],
				mode: "self-signed",
				"trusted-cas": [],
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
