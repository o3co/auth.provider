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
 * Now the same conditions are three values, and what `assembleApp` does with the
 * result is the integration test's business:
 * [`boot/__tests__/discovery-aggregation.integration.test.mts`](../../boot/__tests__/discovery-aggregation.integration.test.mts).
 */

import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { DiscoveryDocumentError } from "#/discovery/buildDocument.mjs";
import {
	type DiscoveryDocumentPlan,
	discoveryRouteFor,
	planDiscoveryDocument,
} from "#/discovery/planRoute.mjs";
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

type PlanInput = Parameters<typeof planDiscoveryDocument>[0];

/** The document step alone, with a default for whatever the case does not set. */
const planDocument = (input: Partial<PlanInput> = {}) =>
	planDiscoveryDocument({
		issuer: ISSUER,
		readSigningAlgs: () => ["HS256"],
		metadata: [providerRoot],
		...input,
	});

/**
 * Both steps, as `assembleApp` runs them: the route when a document is
 * planned, `null` when none is served. A case that expects the document to
 * fail validation reads the planning result directly instead.
 */
const plan = (input: Partial<PlanInput> = {}) => {
	const planning = planDocument(input);
	if (planning.outcome === "invalid")
		throw new Error("unexpected invalid document in a plan() case");
	return planning.outcome === "planned"
		? discoveryRouteFor(planning.plan, () => express.Router())
		: null;
};

describe("planDiscoveryDocument + discoveryRouteFor — the two activation conditions", () => {
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

	it.each([
		["no issuer is configured", { issuer: undefined }],
		["nothing claims to be a provider", { metadata: [jwksOnly] }],
	])("does not read the signing algorithms when %s", (_label, input) => {
		// The key store is a slot a host may fill with an object of its own. A
		// deployment that serves no discovery document never read its
		// algorithm before #626 F4, and does not now: the reader is only called
		// once both activation conditions have passed.
		let read = false;
		const planned = planDocument({
			...input,
			readSigningAlgs: () => {
				read = true;
				return ["HS256"];
			},
		});

		expect(planned).toEqual({ outcome: "not-served" });
		expect(read).toBe(false);
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

describe("planDiscoveryDocument + discoveryRouteFor — what fails, and how", () => {
	it("returns a document that did not validate, rather than throwing it (#650)", () => {
		// A provider root with no key store in the slot: the document cannot
		// claim an algorithm it does not have. It comes back as a VALUE, so the
		// caller can convert exactly this into its own taxonomy and never
		// something else that merely has the same type.
		const planning = planDocument({ readSigningAlgs: () => [] });

		expect(planning.outcome).toBe("invalid");
		expect((planning as { error: unknown }).error).toBeInstanceOf(DiscoveryDocumentError);
	});

	it("returns the builder's own error, not a boot one (#626 F4)", () => {
		// The step names no boot type. `assembleApp` converts this into a
		// `BootError` with `reason: "discovery-document-invalid"`, which is
		// pinned where that conversion lives.
		const planning = planDocument({ metadata: [{ providerRoot: true, metadata: {} }] });

		expect(planning.outcome).toBe("invalid");
		expect((planning as { error: unknown }).error).toBeInstanceOf(DiscoveryDocumentError);
	});

	it.each([
		[
			"the signing-algorithm reader",
			(failure: Error): Partial<PlanInput> => ({
				readSigningAlgs: () => {
					throw failure;
				},
			}),
		],
		[
			"a contribution's providerRoot getter",
			(failure: Error): Partial<PlanInput> => ({
				metadata: [
					{
						get providerRoot(): boolean {
							throw failure;
						},
					},
				],
			}),
		],
	])("throws what %s throws as it is, even a DiscoveryDocumentError (#650)", (_label, input) => {
		// Host-supplied code the planner runs OUTSIDE the builder. An error that
		// merely has the document's type is still not a document that failed
		// to validate, so it is thrown, not returned — the caller never sees it
		// as `outcome: "invalid"`.
		const failure = new DiscoveryDocumentError("not from the builder");

		expect(() => planDocument(input(failure))).toThrow(failure);
	});

	it("builds no router while planning, so a router failure cannot surface as a document error", () => {
		// The router factory is the route step's alone.
		let built = false;
		const planning = planDocument();
		expect(planning.outcome).toBe("planned");
		expect(built).toBe(false);

		const failure = new DiscoveryDocumentError("not from the document");
		expect(() =>
			discoveryRouteFor((planning as { plan: DiscoveryDocumentPlan }).plan, () => {
				built = true;
				throw failure;
			}),
		).toThrow(failure);
		expect(built).toBe(true);
	});
});

describe("planDiscoveryDocument + discoveryRouteFor — what it puts in the document", () => {
	const served = (route: ReturnType<typeof plan>) => {
		const app = express();
		app.use(route?.handler as express.RequestHandler);
		return app;
	};

	it("advertises the signing algorithms it was given", async () => {
		const route = plan({ readSigningAlgs: () => ["ES256"] });

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
