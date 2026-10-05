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
 * dpop `discoveryMetadata` contribution.
 *
 * RFC 9449 §5.1 defines `dpop_signing_alg_values_supported` as authorization
 * server metadata. A client cannot otherwise learn that this deployment
 * accepts DPoP proofs at all, let alone which JOSE algorithms it will verify —
 * so the module that owns the mechanism owns the advertisement, and reads the
 * SAME key of its section the verifier is constructed from.
 */

import {
	type BootstrapMap,
	createApp,
	createMemoryReplaySeenSet,
	createSymmetricKeyStore,
	defineModule,
	type OidcDiscoveryContribution,
} from "@o3co/auth-provider-core";
import {
	CORE_RELOCATIONS,
	createTestOAuthTokenSettings,
	makeValidCoreConfig,
	renamedVariableCaptures,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { dpopConfigSchema, dpopModule } from "#/module.mjs";
import { shippedDpopSection } from "./shippedSection.mjs";

/**
 * The `dpop` section as boot hands it to the module: `written` over the
 * shipped defaults, parsed with `dpopConfigSchema`.
 */
function dpopSection(written: Record<string, unknown> = {}): unknown {
	return dpopConfigSchema.parse(shippedDpopSection(written));
}

async function contribution(section: unknown): Promise<OidcDiscoveryContribution> {
	const factory = dpopModule.contributes?.discoveryMetadata?.[0];
	if (factory === undefined) throw new Error("dpopModule contributes no discoveryMetadata");
	// Awaited, as the boot planner does: a contribution factory may answer with
	// a promise, and every kind's declared type says so.
	return await factory({ section } as never);
}

describe("dpopModule — discoveryMetadata contribution", () => {
	it("advertises dpop_signing_alg_values_supported when DPoP is enabled", async () => {
		const meta = await contribution(dpopSection({ enabled: true }));
		expect(meta.metadata?.dpop_signing_alg_values_supported).toEqual([
			"ES256",
			"ES384",
			"EdDSA",
			"RS256",
		]);
	});

	it("advertises exactly the operator's algWhitelist, not the shipped default", async () => {
		// The advertised list and the list the verifier enforces are the same
		// read. A client that picks an algorithm off discovery must not then be
		// rejected by the proof verifier.
		const meta = await contribution(dpopSection({ enabled: true, algWhitelist: ["ES256"] }));
		expect(meta.metadata?.dpop_signing_alg_values_supported).toEqual(["ES256"]);
	});

	it("is switched off by its section when DPoP is disabled (the secure default), so nothing is contributed", () => {
		expect(dpopModule.section?.isEnabled?.(dpopSection() as never)).toBe(false);
		expect(dpopModule.section?.isEnabled?.(dpopSection({ enabled: true }) as never)).toBe(true);
	});

	it("contributes nothing when algWhitelist is empty, rather than advertising no algorithm", async () => {
		const meta = await contribution(dpopSection({ enabled: true, algWhitelist: [] }));
		const all = { ...(meta.endpoints ?? {}), ...(meta.metadata ?? {}) };
		expect(all).not.toHaveProperty("dpop_signing_alg_values_supported");
	});

	it("is switched off when the dpop section is absent entirely", () => {
		expect(dpopModule.section?.isEnabled?.(dpopConfigSchema.parse(undefined))).toBe(false);
	});

	it("stays an ancillary contributor — it never claims the provider root", async () => {
		// Only the module owning the authorization-server surface sets
		// `providerRoot`; a DPoP-only composition must not cause core to
		// synthesize a discovery document.
		const meta = await contribution(dpopSection({ enabled: true }));
		expect(meta.providerRoot).toBeUndefined();
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

const bootWith = (dpop: Record<string, unknown>): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			dpop: shippedDpopSection(dpop),
			"renamed-variables": renamedVariableCaptures({
				modules: [dpopModule],
				core: CORE_RELOCATIONS,
				env: {},
			}),
		} as never,
		pathResolver: (s: string) => s,
		// An enabled mechanism records every proof in the seen-set, and builds
		// each proof's expected `htu` on the issuer the token settings carry.
		replaySeenSet: createMemoryReplaySeenSet(),
		oauthTokenSettings: createTestOAuthTokenSettings(),
	}) satisfies Record<string, unknown> as BootstrapMap;

describe("dpopModule — discovery metadata in the served document", () => {
	it("serves dpop_signing_alg_values_supported when enabled", async () => {
		const handle = await createApp({
			modules: [dpopModule, keyStoreModule, providerRootModule],
			bootstrapComponents: bootWith({
				enabled: true,
				iatWindowSeconds: 60,
				algWhitelist: ["ES256", "EdDSA"],
				replayStoreTtlSeconds: 300,
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
				iatWindowSeconds: 60,
				algWhitelist: ["ES256", "ES384", "EdDSA", "RS256"],
				replayStoreTtlSeconds: 300,
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
