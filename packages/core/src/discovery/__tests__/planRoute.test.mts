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
 * The planner as a function of its inputs (#626 F4).
 *
 * It could not be tested this way before: it took `assembleApp`'s frozen world
 * and cast three readings out of it, so every case needed a boot fixture and
 * the two activation conditions were only ever exercised through a whole boot.
 * Now the same conditions are four values, and what `assembleApp` does with the
 * result is the integration test's business:
 * [`boot/__tests__/discovery-aggregation.integration.test.mts`](../../boot/__tests__/discovery-aggregation.integration.test.mts).
 */

import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { DiscoveryDocumentError } from "#/discovery/buildDocument.mjs";
import { planDiscoveryRoute } from "#/discovery/planRoute.mjs";
import type { OidcDiscoveryContribution } from "#/discovery/types.mjs";

const ISSUER = "https://auth.example.com";

/**
 * A provider-root contribution that assembles into a valid document. Endpoints
 * go in `endpoints` (issuer-prefixed and checked) and literals in `metadata` —
 * the aggregator refuses an issuer-relative path put in the latter.
 */
const providerRoot: OidcDiscoveryContribution = {
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
};

/** An ancillary contributor: publishes a key set, claims no provider. */
const jwksOnly: OidcDiscoveryContribution = {
	endpoints: { jwks_uri: "/.well-known/jwks.json" },
};

const plan = (input: Partial<Parameters<typeof planDiscoveryRoute>[0]> = {}) =>
	planDiscoveryRoute({
		issuer: ISSUER,
		signingAlgs: ["HS256"],
		metadata: [providerRoot],
		routerFactory: () => express.Router(),
		...input,
	});

describe("planDiscoveryRoute — the two activation conditions", () => {
	it("plans a route when an issuer is configured and something claims to be a provider", () => {
		const route = plan();

		expect(route).not.toBeNull();
		expect(route?.id).toBe("core:oidc-discovery");
		expect(route?.mountPath).toBe("/");
		// #528: both well-known forms, one handler, so the two cannot differ.
		expect(route?.routes.map((r) => r.path)).toEqual([
			"/.well-known/openid-configuration",
			"/.well-known/oauth-authorization-server",
		]);
	});

	it.each([
		["nothing", undefined],
		["the empty string", ""],
	])("declines when the issuer is %s", (_label, issuer) => {
		// #266 made `oauth.jwt.issuer` required at the schema boundary, so this
		// is unreachable through boot. The guard is for a caller that arrives
		// with a config that never passed the schema — a hand-built `AppConfig`
		// through `bootstrapComponents`, which is not checked at the boundary it
		// crosses — which is why it is pinned here rather than through a boot
		// fixture that cannot be built.
		expect(plan({ issuer })).toBeNull();
	});

	it("declines when nothing declares itself a provider root", () => {
		// `providerRoot` is the EXPLICIT signal. A deployment that only
		// publishes a key set mounts JWKS without being advertised as an
		// OpenID Provider.
		expect(plan({ metadata: [jwksOnly] })).toBeNull();
	});

	it("declines when no contribution was made at all", () => {
		expect(plan({ metadata: [] })).toBeNull();
	});

	it("declines before it would build a document, so an inactive deployment cannot fail on one", () => {
		// The provider-root gate runs first. A contribution set that would not
		// assemble is not a boot failure when nothing claimed to be a provider.
		expect(() => plan({ metadata: [{ metadata: {} }] })).not.toThrow();
		expect(plan({ metadata: [{ metadata: {} }] })).toBeNull();
	});
});

describe("planDiscoveryRoute — what it raises", () => {
	it("refuses to assemble a document that advertises no signing algorithm", () => {
		// A provider root with no key store in the slot: the caller passes an
		// empty list and the document cannot claim an algorithm it does not
		// have. `assembleApp` turns this into a boot failure, which is the
		// point — an OP that cannot name how it signs is a misconfiguration,
		// not a document with a missing field.
		expect(() => plan({ signingAlgs: [] })).toThrow(DiscoveryDocumentError);
	});

	it("raises the document's own error, not the boot stage's (#626 F4)", () => {
		// The step names no boot type. `assembleApp` converts this into a
		// `BootError` with `reason: "discovery-document-invalid"`, which is
		// pinned where that conversion lives — naming it here would mean
		// importing the stage into the step it is a step of.
		expect(() => plan({ metadata: [{ providerRoot: true, metadata: {} }] })).toThrow(
			DiscoveryDocumentError,
		);
	});
});

describe("planDiscoveryRoute — what it puts in the document", () => {
	const served = (route: ReturnType<typeof planDiscoveryRoute>) => {
		const app = express();
		app.use(route?.handler as express.RequestHandler);
		return app;
	};

	it("advertises the signing algorithms it was given", async () => {
		const route = plan({ signingAlgs: ["ES256"] });

		const res = await request(served(route)).get("/.well-known/openid-configuration");

		expect(res.status).toBe(200);
		expect(res.body.id_token_signing_alg_values_supported).toEqual(["ES256"]);
	});

	it("serves the same body at both well-known paths", async () => {
		const app = served(plan());

		const oidc = await request(app).get("/.well-known/openid-configuration");
		const rfc8414 = await request(app).get("/.well-known/oauth-authorization-server");

		expect(oidc.status).toBe(200);
		expect(rfc8414.status).toBe(200);
		expect(rfc8414.body).toEqual(oidc.body);
	});

	it("passes a request for anything else through", async () => {
		const app = express();
		app.use(plan()?.handler as express.RequestHandler);
		app.get("/elsewhere", (_req, res) => {
			res.status(200).json({ mine: true });
		});

		const res = await request(app).get("/elsewhere");

		expect(res.body).toEqual({ mine: true });
	});
});
