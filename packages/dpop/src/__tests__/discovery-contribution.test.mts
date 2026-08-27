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
 * dpop `discoveryMetadata` contribution (#283).
 *
 * RFC 9449 §5.1 defines `dpop_signing_alg_values_supported` as authorization
 * server metadata. A client cannot otherwise learn that this deployment
 * accepts DPoP proofs at all, let alone which JOSE algorithms it will verify —
 * so the module that owns the mechanism owns the advertisement, and reads the
 * SAME config key the verifier is constructed from.
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
import { dpopModule } from "#/module.mjs";

/** Build the dpop config slice as `dpopConfigSchema` would leave it. */
function dpopConfig(overrides: Record<string, unknown> = {}): unknown {
	return {
		oauth: {
			dpop: {
				enabled: false,
				"iat-window-seconds": 60,
				"alg-whitelist": ["ES256", "ES384", "EdDSA", "RS256"],
				"replay-store": "memory",
				"replay-store-ttl-seconds": 300,
				...overrides,
			},
		},
	};
}

function contribution(config: unknown): OidcDiscoveryContribution {
	const factory = dpopModule.contributes?.discoveryMetadata?.[0];
	if (factory === undefined) throw new Error("dpopModule contributes no discoveryMetadata");
	return factory({ config } as never);
}

describe("dpopModule — discoveryMetadata contribution", () => {
	it("advertises dpop_signing_alg_values_supported when DPoP is enabled", () => {
		const meta = contribution(dpopConfig({ enabled: true }));
		expect(meta.metadata?.dpop_signing_alg_values_supported).toEqual([
			"ES256",
			"ES384",
			"EdDSA",
			"RS256",
		]);
	});

	it("advertises exactly the operator's alg-whitelist, not the shipped default", () => {
		// The advertised list and the list the verifier enforces are the same
		// read. A client that picks an algorithm off discovery must not then be
		// rejected by the proof verifier.
		const meta = contribution(dpopConfig({ enabled: true, "alg-whitelist": ["ES256"] }));
		expect(meta.metadata?.dpop_signing_alg_values_supported).toEqual(["ES256"]);
	});

	it("contributes nothing when DPoP is disabled (the secure default)", () => {
		const meta = contribution(dpopConfig());
		const all = { ...(meta.endpoints ?? {}), ...(meta.metadata ?? {}) };
		expect(all).not.toHaveProperty("dpop_signing_alg_values_supported");
	});

	it("contributes nothing when the oauth.dpop slice is absent entirely", () => {
		const meta = contribution({ oauth: {} });
		const all = { ...(meta.endpoints ?? {}), ...(meta.metadata ?? {}) };
		expect(all).not.toHaveProperty("dpop_signing_alg_values_supported");
	});

	it("stays an ancillary contributor — it never claims the provider root", () => {
		// Only the module owning the authorization-server surface sets
		// `providerRoot`; a DPoP-only composition must not cause core to
		// synthesize a discovery document.
		expect(contribution(dpopConfig({ enabled: true })).providerRoot).toBeUndefined();
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
		keyStore: () => createSymmetricKeyStore("test-secret-for-dpop-discovery!!!"),
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

const bootWith = (dpop: Record<string, unknown>): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			oauth: { ...makeValidCoreConfig().oauth, dpop },
		} as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

describe("dpopModule — discovery metadata in the served document", () => {
	it("serves dpop_signing_alg_values_supported when enabled", async () => {
		const handle = await createApp({
			modules: [dpopModule, keyStoreModule, providerRootModule],
			bootstrapComponents: bootWith({
				enabled: true,
				"iat-window-seconds": 60,
				"alg-whitelist": ["ES256", "EdDSA"],
				"replay-store": "memory",
				"replay-store-ttl-seconds": 300,
			}),
		});
		const app = express();
		app.use(handle.router);
		const { body } = await request(app).get("/.well-known/openid-configuration");
		expect(body.dpop_signing_alg_values_supported).toEqual(["ES256", "EdDSA"]);
		await handle.dispose();
	});

	it("serves a document without the field when disabled — and still boots", async () => {
		const handle = await createApp({
			modules: [dpopModule, keyStoreModule, providerRootModule],
			bootstrapComponents: bootWith({
				enabled: false,
				"iat-window-seconds": 60,
				"alg-whitelist": ["ES256", "ES384", "EdDSA", "RS256"],
				"replay-store": "memory",
				"replay-store-ttl-seconds": 300,
			}),
		});
		const app = express();
		app.use(handle.router);
		const { status, body } = await request(app).get("/.well-known/openid-configuration");
		expect(status).toBe(200);
		expect(body).not.toHaveProperty("dpop_signing_alg_values_supported");
		await handle.dispose();
	});
});
