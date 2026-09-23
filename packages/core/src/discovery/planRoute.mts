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
 * {@link planDiscoveryRoute} and gets back either a normal route contribution
 * or `null`; from `assembleApp`'s perspective discovery is just another route
 * that flows through the standard collision-check + mount-order + mount
 * pipeline — no special-casing.
 *
 * It takes VALUES, not the boot world (#626 F4). Until then it took
 * `assembleApp`'s own `Readonly<Partial<ComponentMap>>` widened to
 * `Record<string, unknown>` and cast three readings back out of it, and it
 * imported `BootError` from `boot/` to raise one — so the domain step and the
 * boot step referenced each other, and a typed map was laundered through
 * `unknown` to do it. Neither is needed: the caller already holds both values
 * typed, and the error taxonomy belongs to the stage that owns the taxonomy.
 */

import type { NextFunction, Request, Response, Router } from "express";
import type { RouteContribution, RouteHandler } from "../modules/manifest/route-contribution.mjs";
import { buildDiscoveryDocument } from "./buildDocument.mjs";
import type { OidcDiscoveryContribution } from "./types.mjs";
import { discoveryPathsFor } from "./wellKnownPaths.mjs";

/** Stable id for the core-synthesized discovery route (used for collision identity). */
const DISCOVERY_ROUTE_ID = "core:oidc-discovery";

/**
 * Plan the core-synthesized OIDC discovery route from the aggregated
 * `discoveryMetadata` contributions, or return `null` when discovery should not
 * be served.
 *
 * Returns a route contribution (mounted at "/", advertising `GET` on every
 * path the document is served at — OIDC Discovery's
 * `/.well-known/openid-configuration` and RFC 8414's
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
 * The assembled document is validated by {@link buildDiscoveryDocument}, whose
 * `DiscoveryDocumentError` (missing required field, reserved-field
 * contribution, conflicting values, …) is raised as it is. The caller turns it
 * into whatever its own failure taxonomy is — `boot/assemble-app.mts` wraps it
 * in a `BootError` with `reason: "discovery-document-invalid"`, so discovery
 * misconfiguration still surfaces the way every other assembleApp error does.
 * Naming that error here would mean importing the boot stage into the step it
 * is a step of (#626 F4).
 *
 * @throws DiscoveryDocumentError when the contributions do not assemble into a
 * valid document.
 */
export function planDiscoveryRoute(input: {
	/**
	 * `config.oauth.jwt.issuer`. `undefined` when the deployment configured
	 * none, which is the first of the two activation conditions above.
	 */
	readonly issuer: string | undefined;
	/**
	 * What the document advertises as `id_token_signing_alg_values_supported`;
	 * empty when no key store named an algorithm.
	 */
	readonly signingAlgs: readonly string[];
	/** Every `discoveryMetadata` contribution, in registration order. */
	readonly metadata: readonly OidcDiscoveryContribution[];
	readonly routerFactory: () => Router;
}): RouteContribution | null {
	const { issuer, signingAlgs, metadata, routerFactory } = input;

	// #266 made `oauth.jwt.issuer` required at the schema boundary, so a config
	// that passed the schema always has one. The guard is for a caller that
	// reaches here with one that did not — a hand-built `AppConfig` through
	// `bootstrapComponents`, which is not type-checked at the boundary it
	// crosses.
	if (typeof issuer !== "string" || issuer.length === 0) return null;

	if (!metadata.some((item) => item.providerRoot === true)) return null;

	const doc: Record<string, unknown> = buildDiscoveryDocument(metadata, { issuer, signingAlgs });

	// #528: one document, every path a client may look for it at — OIDC's
	// appended form and RFC 8414's inserted form — through one handler, so
	// the bodies and headers cannot differ between them.
	const discovery = discoveryPathsFor(issuer);
	const paths = [...discovery.oidc, ...discovery.oauth];
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
