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
 * Keeps ALL OIDC-specific knowledge (the issuer config path, the keyStore
 * signing algorithm, provider activation, document construction + validation,
 * and the spec-fixed discovery path) out of the generic boot planner
 * (`boot/assemble-app.mts`). The planner calls {@link planDiscoveryRoute} and
 * gets back either a normal route contribution or `null`; from `assembleApp`'s
 * perspective discovery is just another route that flows through the standard
 * collision-check + mount-order + mount pipeline — no special-casing.
 */

import type { Router } from "express";
import { BootError, type ListCollector } from "../boot/types.mjs";
import type { RouteContribution, RouteHandler } from "../modules/manifest/route-contribution.mjs";
import { buildDiscoveryDocument, DiscoveryDocumentError } from "./buildDocument.mjs";
import type { OidcDiscoveryContribution } from "./types.mjs";

/** The RFC 8414 / OIDC Discovery 1.0 fixed discovery path. */
const OIDC_DISCOVERY_PATH = "/.well-known/openid-configuration";

/** Stable id for the core-synthesized discovery route (used for collision identity). */
const DISCOVERY_ROUTE_ID = "core:oidc-discovery";

/**
 * Plan the core-synthesized OIDC discovery route from the aggregated
 * `discoveryMetadata` contributions, or return `null` when discovery should not
 * be served.
 *
 * Returns a route contribution (mounted at "/", advertising
 * `GET /.well-known/openid-configuration`) when BOTH:
 *   1. an issuer is configured (`config.oauth.jwt.issuer`), and
 *   2. some contribution declares `providerRoot: true` — the EXPLICIT
 *      "an OpenID Provider exists here" signal. An ancillary contributor like
 *      the JWKS module (only `jwks_uri`) leaves it unset, so a key-publishing
 *      deployment can mount JWKS without being treated as a provider; and a
 *      provider that does not expose `authorization_endpoint` (CIBA, device
 *      flow) still activates discovery instead of silently serving nothing.
 *
 * The assembled document is validated by {@link buildDiscoveryDocument}; a
 * `DiscoveryDocumentError` (missing required field, reserved-field
 * contribution, conflicting values, …) is wrapped in a `BootError`
 * (`reason: "discovery-document-invalid"`) so discovery misconfiguration
 * surfaces through the same boot-failure taxonomy as every other assembleApp
 * error.
 */
export function planDiscoveryRoute(input: {
	readonly components: Record<string, unknown>;
	readonly registries: ReadonlyMap<string, unknown>;
	readonly routerFactory: () => Router;
}): RouteContribution | null {
	const { components, registries, routerFactory } = input;

	const config = components.config as { oauth?: { jwt?: { issuer?: unknown } } } | undefined;
	const issuer = config?.oauth?.jwt?.issuer;
	if (typeof issuer !== "string" || issuer.length === 0) return null;

	const collector = registries.get("discoveryMetadata") as
		| ListCollector<OidcDiscoveryContribution>
		| undefined;
	const items = collector !== undefined ? [...collector.values()] : [];
	if (!items.some((item) => item.providerRoot === true)) return null;

	const keyStore = components.keyStore as { algorithm?: unknown } | undefined;
	const signingAlgs = typeof keyStore?.algorithm === "string" ? [keyStore.algorithm] : [];

	let doc: Record<string, unknown>;
	try {
		doc = buildDiscoveryDocument(items, { issuer, signingAlgs });
	} catch (err) {
		if (err instanceof DiscoveryDocumentError) {
			throw new BootError({
				message: `assembleApp: ${err.message}`,
				reason: "discovery-document-invalid",
				stage: "assembleApp",
				details: { reason: "discovery-document-invalid", detail: err.message },
				cause: err,
			});
		}
		throw err;
	}

	const router = routerFactory();
	router.get(OIDC_DISCOVERY_PATH, (_req, res) => {
		res.status(200).json(doc);
	});

	return {
		id: DISCOVERY_ROUTE_ID,
		mountPath: "/",
		handler: router as RouteHandler,
		routes: [{ method: "GET", path: OIDC_DISCOVERY_PATH }],
	};
}
