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

import type { DiscoveryMetadata } from "./types.mjs";

/**
 * Discovery fields owned by the aggregator itself — a module contribution may
 * NOT set them (doing so is a boot error). `issuer` is the deployment identity
 * and `id_token_signing_alg_values_supported` reflects what the `keyStore` can
 * actually sign, so neither is a per-module concern.
 */
const RESERVED_FIELDS = new Set(["issuer", "id_token_signing_alg_values_supported"]);

/**
 * OIDC Discovery 1.0 §3 REQUIRED fields. The assembled document must carry all
 * of them, else the deployment is advertising a malformed discovery document —
 * a boot error. This is what makes the cross-module presence contract
 * structural: `jwks_uri` is required, so a composition that advertises an
 * issuer but omits the JWKS-contributing module fails fast at boot instead of
 * serving a document with a missing `jwks_uri`.
 */
const REQUIRED_FIELDS = [
	"issuer",
	"authorization_endpoint",
	"token_endpoint",
	"jwks_uri",
	"response_types_supported",
	"subject_types_supported",
	"id_token_signing_alg_values_supported",
] as const;

/**
 * The OpenID-Provider-defining endpoint. A composition is treated as an OpenID
 * Provider — and therefore expected to serve a discovery document — only when
 * some module contributes this endpoint. Modules that contribute ONLY ancillary
 * endpoints (notably the JWKS module's `jwks_uri`) do not by themselves make
 * the deployment a provider, so they must not trigger discovery aggregation: a
 * key-publishing deployment can mount JWKS without the full OAuth suite even
 * with an issuer configured. `authorization_endpoint` is OIDC Discovery 1.0
 * §3's first REQUIRED endpoint and the canonical marker that an authorization
 * server exists. See {@link contributesProviderSurface}.
 */
const PROVIDER_SURFACE_FIELD = "authorization_endpoint";

/**
 * Whether the contributions declare an OpenID Provider surface (vs. only
 * ancillary endpoints like `jwks_uri`). The aggregator uses this to decide
 * whether to synthesize + mount the discovery document at all: only once a
 * provider-defining endpoint is contributed does the OIDC presence contract
 * (all REQUIRED fields present, else boot fails) apply. This reproduces the
 * pre-aggregator trigger — "the OAuth module is wired and an issuer is set" —
 * without core having to name the oauth module.
 */
export function contributesProviderSurface(items: readonly DiscoveryMetadata[]): boolean {
	return items.some((item) => item.endpoints?.[PROVIDER_SURFACE_FIELD] !== undefined);
}

/** Thrown when module `discoveryMetadata` contributions cannot form a valid document. */
export class DiscoveryDocumentError extends Error {
	override readonly name = "DiscoveryDocumentError";
}

// `Set`-based identity dedup. All discovery array fields today carry primitive
// (string) elements — `scopes_supported`, `*_methods_supported`, signing algs —
// so identity equality IS value equality. A future contribution supplying an
// array of objects would not be value-deduped; revisit this if that arises.
function dedupe(values: readonly unknown[]): unknown[] {
	const seen = new Set<unknown>();
	const out: unknown[] = [];
	for (const v of values) {
		if (!seen.has(v)) {
			seen.add(v);
			out.push(v);
		}
	}
	return out;
}

/**
 * Aggregate every module's {@link DiscoveryMetadata} contribution into the
 * single OIDC discovery document.
 *
 * The aggregator owns `issuer` (trailing-slash-normalized) and
 * `id_token_signing_alg_values_supported` (from the keyStore). Module
 * contributions supply issuer-relative `endpoints` (prefixed with the issuer
 * here) and literal `metadata` (arrays concatenated + de-duplicated; scalars
 * must agree). Conflicting values, reserved-field contributions, non-absolute
 * endpoint paths, and a document missing any OIDC-required field all throw
 * {@link DiscoveryDocumentError} — surfaced as a boot error so misconfiguration
 * fails fast rather than serving a malformed document.
 *
 * Items are processed in caller-supplied (module-registration) order, so the
 * output is deterministic.
 */
export function buildDiscoveryDocument(
	items: readonly DiscoveryMetadata[],
	opts: { readonly issuer: string; readonly signingAlgs: readonly string[] },
): Record<string, unknown> {
	const issuer = opts.issuer.replace(/\/+$/, "");
	// An all-slashes issuer (e.g. "/", "//") passes the assemble-app gate
	// (`issuerValue.length > 0` on the RAW value) but normalizes to "" here,
	// which would emit `issuer: ""` and origin-less endpoint URLs. That is a
	// misconfiguration, so fail the boot fast rather than advertising a
	// malformed document.
	if (issuer === "") {
		throw new DiscoveryDocumentError(
			`discovery issuer must not be empty after trailing-slash normalization (got ${JSON.stringify(opts.issuer)})`,
		);
	}
	const doc: Record<string, unknown> = {
		issuer,
		id_token_signing_alg_values_supported: dedupe(opts.signingAlgs),
	};

	for (const item of items) {
		for (const [field, path] of Object.entries(item.endpoints ?? {})) {
			if (RESERVED_FIELDS.has(field)) {
				throw new DiscoveryDocumentError(
					`discoveryMetadata may not contribute the reserved field "${field}" (owned by the aggregator)`,
				);
			}
			if (typeof path !== "string" || !path.startsWith("/")) {
				throw new DiscoveryDocumentError(
					`discoveryMetadata endpoint "${field}" must be an absolute path beginning with "/", got ${JSON.stringify(path)}`,
				);
			}
			const url = `${issuer}${path}`;
			if (field in doc && doc[field] !== url) {
				throw new DiscoveryDocumentError(
					`discoveryMetadata field "${field}" was contributed with conflicting values (${JSON.stringify(doc[field])} vs ${JSON.stringify(url)})`,
				);
			}
			doc[field] = url;
		}

		for (const [field, value] of Object.entries(item.metadata ?? {})) {
			if (RESERVED_FIELDS.has(field)) {
				throw new DiscoveryDocumentError(
					`discoveryMetadata may not contribute the reserved field "${field}" (owned by the aggregator)`,
				);
			}
			if (Array.isArray(value)) {
				const existing = doc[field];
				if (existing !== undefined && !Array.isArray(existing)) {
					throw new DiscoveryDocumentError(
						`discoveryMetadata field "${field}" was contributed as both an array and a scalar`,
					);
				}
				doc[field] = dedupe([...((existing as unknown[] | undefined) ?? []), ...value]);
			} else {
				if (field in doc && doc[field] !== value) {
					throw new DiscoveryDocumentError(
						`discoveryMetadata field "${field}" was contributed with conflicting values (${JSON.stringify(doc[field])} vs ${JSON.stringify(value)})`,
					);
				}
				doc[field] = value;
			}
		}
	}

	const missing = REQUIRED_FIELDS.filter((f) => doc[f] === undefined);
	if (missing.length > 0) {
		throw new DiscoveryDocumentError(
			`discovery document is missing OIDC-required field(s): ${missing.join(", ")}. ` +
				`Ensure every endpoint-owning module (e.g. the OAuth module and the JWKS module) is wired ` +
				`when an issuer is configured.`,
		);
	}

	return doc;
}
