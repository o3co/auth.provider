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
 * discovery/planRoute.mts — the OIDC discovery subsystem's boot-planner hook.
 *
 * Keeps ALL OIDC-specific knowledge (provider activation, document
 * construction + validation, and the spec-fixed discovery paths) out of the
 * generic boot planner (`boot/assemble-app.mts`). The planner calls
 * {@link planDiscoveryDocument} and, when a document is planned,
 * {@link discoveryRouteFor}, and gets back a normal route contribution; from
 * `assembleApp`'s perspective discovery is just another route that flows
 * through the standard collision-check + mount-order + mount pipeline — no
 * special-casing.
 *
 * It takes VALUES, not the boot world (#626 F4). Until then it took
 * `assembleApp`'s own `Readonly<Partial<ComponentMap>>` widened to
 * `Record<string, unknown>` and cast three readings back out of it, and it
 * imported `BootError` from `boot/` to raise one — so the domain step and the
 * boot step referenced each other, and a typed map was laundered through
 * `unknown` to do it. Neither is needed: the caller already holds both values
 * typed, and the error taxonomy belongs to the stage that owns the taxonomy.
 *
 * A document that failed to validate is RETURNED, not thrown. The caller
 * converts it into its own failure taxonomy, and it must convert exactly that
 * and nothing else — which a `try` around the planner could not promise: the
 * planner also runs host-supplied code (the key store's algorithm, the
 * contributions' getters, the collector, the router factory), and any of it
 * could throw an error that merely has the right type. Two review rounds on
 * #650 found one such path each. Catching only around
 * {@link buildDiscoveryDocument} here and handing the error back as a value
 * makes provenance structural: the caller cannot mistake anything else for
 * it, because nothing else arrives as a value.
 *
 * {@link discoveryRouteFor} builds the route for a planned document,
 * separately, because it calls the router factory.
 */

import type { NextFunction, Request, Response, Router } from "express";
import type { RouteContribution, RouteHandler } from "../modules/manifest/route-contribution.mjs";
import { buildDiscoveryDocument, DiscoveryDocumentError } from "./buildDocument.mjs";
import type { OidcDiscoveryContribution } from "./types.mjs";
import { discoveryPathsFor } from "./wellKnownPaths.mjs";

/** Stable id for the core-synthesized discovery route (used for collision identity). */
const DISCOVERY_ROUTE_ID = "core:oidc-discovery";

/**
 * A document that will be served, and every path it is served at. What
 * {@link planDiscoveryDocument} decides and {@link discoveryRouteFor} serves.
 */
export interface DiscoveryDocumentPlan {
	readonly document: Readonly<Record<string, unknown>>;
	readonly paths: readonly string[];
}

/**
 * What {@link planDiscoveryDocument} decided. `"invalid"` carries the error
 * {@link buildDiscoveryDocument} raised, and only that: nothing else the
 * planner runs can produce this outcome.
 */
export type DiscoveryDocumentPlanning =
	| { readonly outcome: "not-served" }
	| { readonly outcome: "planned"; readonly plan: DiscoveryDocumentPlan }
	| { readonly outcome: "invalid"; readonly error: DiscoveryDocumentError };

/**
 * Decide whether the core-synthesized OIDC discovery document is served, and
 * assemble it — or return `null` when it is not.
 *
 * A document is served (at every path a client may look for it at — OIDC
 * Discovery's `/.well-known/openid-configuration` and RFC 8414's
 * `/.well-known/oauth-authorization-server`, formed per the issuer's path
 * component by {@link discoveryPathsFor}, #528) when BOTH:
 *   1. an issuer is configured (`config.oauth.jwt.issuer`), and
 *   2. some contribution declares `providerRoot: true` — the EXPLICIT
 *      "an OpenID Provider exists here" signal. An ancillary contributor like
 *      the JWKS module (only `jwks_uri`) leaves it unset, so a key-publishing
 *      deployment can mount JWKS without being treated as a provider; and a
 *      provider that does not expose `authorization_endpoint` (CIBA, device
 *      flow) still activates discovery instead of silently serving nothing.
 *
 * The document is validated by {@link buildDiscoveryDocument}. A
 * `DiscoveryDocumentError` it raises (missing required field, reserved-field
 * contribution, conflicting values, …) comes back as `outcome: "invalid"`, and
 * the caller turns it into its own failure taxonomy — `boot/assemble-app.mts`
 * into a `BootError` with `reason: "discovery-document-invalid"`. Naming that
 * error here would mean importing the boot stage into the step it is a step
 * of (#626 F4).
 *
 * Anything else is thrown as it is, whatever its type. That includes a
 * `DiscoveryDocumentError` from the host-supplied code this runs outside the
 * builder — the signing-algorithm reader and a contribution's `providerRoot`
 * getter: those are not a document that failed to validate. What runs INSIDE
 * the builder is the builder's, which is the boundary the conversion had
 * before #626 F4 moved it.
 *
 * Builds no router.
 */
export function planDiscoveryDocument(input: {
	/**
	 * `config.oauth.jwt.issuer`. `undefined` when the deployment configured
	 * none, which is the first of the two activation conditions above.
	 */
	readonly issuer: string | undefined;
	/**
	 * What the document advertises as `id_token_signing_alg_values_supported`;
	 * empty when no key store named an algorithm.
	 *
	 * A reader rather than a value, so that it is only read once both
	 * activation conditions have passed — as it was before #626 F4 moved it.
	 * The key store is a slot a host may fill with an object of its own, and
	 * a deployment that serves no discovery document has never touched its
	 * algorithm.
	 */
	readonly readSigningAlgs: () => readonly string[];
	/** Every `discoveryMetadata` contribution, in registration order. */
	readonly metadata: readonly OidcDiscoveryContribution[];
}): DiscoveryDocumentPlanning {
	const { issuer, readSigningAlgs, metadata } = input;

	// #266 made `oauth.jwt.issuer` required at the schema boundary, so a config
	// that passed the schema always has one. The guard is for a caller that
	// reaches here with one that did not — a hand-built `AppConfig` through
	// `bootstrapComponents`, which is not type-checked at the boundary it
	// crosses.
	if (typeof issuer !== "string" || issuer.length === 0) return { outcome: "not-served" };

	if (!metadata.some((item) => item.providerRoot === true)) return { outcome: "not-served" };

	// Read before the builder runs, and outside its catch: the reader is
	// host-supplied code, and what it throws is not a document that failed to
	// validate.
	const signingAlgs = readSigningAlgs();

	let document: Record<string, unknown>;
	try {
		document = buildDiscoveryDocument(metadata, { issuer, signingAlgs });
	} catch (err) {
		if (err instanceof DiscoveryDocumentError) return { outcome: "invalid", error: err };
		throw err;
	}

	// #528: one document, every path a client may look for it at — OIDC's
	// appended form and RFC 8414's inserted form — through one handler, so
	// the bodies and headers cannot differ between them.
	const discovery = discoveryPathsFor(issuer);
	return { outcome: "planned", plan: { document, paths: [...discovery.oidc, ...discovery.oauth] } };
}

/**
 * The route that serves a planned document: an ordinary route contribution,
 * mounted at "/", advertising `GET` on each of the plan's paths.
 *
 * Raises no document error — the document was assembled and validated by
 * {@link planDiscoveryDocument} already. What it can raise is whatever the
 * router factory raises, and that is not a discovery misconfiguration.
 */
export function discoveryRouteFor(
	plan: DiscoveryDocumentPlan,
	routerFactory: () => Router,
): RouteContribution {
	const { document: doc, paths } = plan;
	const router = routerFactory();
	// These paths are literals, not route patterns. An issuer is a URL and
	// its path may hold characters Express 5's parser reads as syntax —
	// `+`, `*`, `(`, `)`, `:`, `{}` — so `router.get(path)` on
	// `https://as.example/tenant+blue` either throws at boot or matches
	// requests this server never advertised. Matching the pathname itself
	// keeps the route exactly what the document says it is, which is also
	// what RFC 8414 §3.3 requires of the two to agree.
	//
	// Exactly, but for a trailing slash: Express's default non-strict
	// routing accepted one and clients send it, so that stays. Case is not
	// folded — a well-known URI is case-sensitive (RFC 8615 §3), and an
	// issuer identifier is compared as a string (RFC 8414 §3.3), so the two
	// cannot be allowed to differ by case here.
	const advertised = new Set(paths);
	const trimTrailingSlash = (path: string): string =>
		path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;
	router.use((req: Request, res: Response, next: NextFunction): void => {
		if (req.method !== "GET" && req.method !== "HEAD") {
			next();
			return;
		}
		if (!advertised.has(trimTrailingSlash(req.path))) {
			next();
			return;
		}
		res.status(200).json(doc);
	});

	return {
		id: DISCOVERY_ROUTE_ID,
		mountPath: "/",
		handler: router as RouteHandler,
		routes: paths.map((path) => ({ method: "GET" as const, path })),
	};
}
