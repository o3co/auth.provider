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
 * The OIDC discovery subsystem's boot-planner hook. Keeps OIDC-specific
 * knowledge (activation, document construction and validation, the discovery
 * paths) out of `boot/assemble-app.mts`: the planner calls
 * {@link planDiscoveryDocument}, then {@link discoveryRouteFor}, and gets an
 * ordinary route contribution.
 *
 * Takes values rather than the boot component map and does not import
 * `boot/`: the error taxonomy belongs to the boot stage.
 *
 * A document that fails validation is returned, not thrown, so the caller
 * converts exactly that error and nothing else. The planner also runs
 * host-supplied code (the algorithm reader, the metadata collector,
 * `providerRoot` getters) that may throw an error of the same type; only what
 * raises while {@link buildDiscoveryDocument} runs, including a contribution's
 * `endpoints`/`metadata` getters it reads, comes back as `"invalid"`.
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
 * assemble it.
 *
 * Served, at every path a client may look for it (OIDC Discovery's
 * `/.well-known/openid-configuration` and RFC 8414's
 * `/.well-known/oauth-authorization-server`, see {@link discoveryPathsFor}),
 * when both:
 *   1. an issuer is configured (`config.oauth.jwt.issuer`), and
 *   2. some contribution declares `providerRoot: true`. The explicit signal
 *      lets a deployment publish JWKS without becoming a provider, and lets a
 *      provider without `authorization_endpoint` (CIBA, device flow) still
 *      activate discovery.
 *
 * A `DiscoveryDocumentError` raised by {@link buildDiscoveryDocument} comes
 * back as `outcome: "invalid"`; `boot/assemble-app.mts` turns it into a
 * `BootError` (`discovery-document-invalid`). Anything else is rethrown,
 * including a `DiscoveryDocumentError` from host code run outside the builder.
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
	 * empty when no key store named an algorithm. A reader, so the host-supplied
	 * key store is touched only once both activation conditions have passed.
	 */
	readonly readSigningAlgs: () => readonly string[];
	/**
	 * Every `discoveryMetadata` contribution, in registration order. A reader,
	 * so the host-supplied collector is not iterated before the issuer gate.
	 */
	readonly readMetadata: () => readonly OidcDiscoveryContribution[];
}): DiscoveryDocumentPlanning {
	const { issuer, readSigningAlgs, readMetadata } = input;

	// The schema requires `oauth.jwt.issuer`; this guards a hand-built
	// `AppConfig` passed through `bootstrapComponents`, which is not validated.
	if (typeof issuer !== "string" || issuer.length === 0) return { outcome: "not-served" };

	// Host-supplied inputs are read in the order the planner needs them: the
	// collector after the issuer gate, the algorithms after both.
	const metadata = readMetadata();
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

	// One document, every path a client may look for it at (OIDC's appended
	// form and RFC 8414's inserted form), through one handler, so the bodies
	// and headers cannot differ between them.
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
	// Match the pathname literally, not as a route pattern: an issuer path may
	// hold characters Express 5 parses as syntax (`+`, `*`, `(`, `)`, `:`,
	// `{}`), which would throw at boot or match paths never advertised, and
	// RFC 8414 §3.3 requires route and document to agree. A trailing slash is
	// tolerated (clients send it); case is not folded, since well-known URIs are
	// case-sensitive (RFC 8615 §3) and issuers compare as strings.
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
