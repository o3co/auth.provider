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

import type { OidcDiscoveryContribution } from "./types.mjs";

/**
 * Discovery fields owned by the aggregator itself — a module contribution may
 * NOT set them (doing so is a boot error). `issuer` is the deployment identity
 * and `id_token_signing_alg_values_supported` reflects what the `keyStore` can
 * actually sign, so neither is a per-module concern.
 */
const RESERVED_FIELDS = new Set(["issuer", "id_token_signing_alg_values_supported"]);

/**
 * The fields every assembled document carries, else it is malformed — a boot
 * error. `jwks_uri` is among them, so a composition that advertises an issuer
 * but omits the JWKS-contributing module fails at boot instead of serving a
 * document with no `jwks_uri`. `authorization_endpoint` is not: RFC 8414 §2
 * requires it only when a grant uses it, which {@link checkAuthorizationEndpoint}
 * holds against `response_types_supported`. A document without it is an
 * authorization server's and not an OpenID Provider's — OpenID Connect
 * Discovery §3 requires the endpoint of every OP — and is served at both
 * discovery paths all the same, where a resource server finds the keys.
 */
const REQUIRED_FIELDS = [
	"issuer",
	"token_endpoint",
	"jwks_uri",
	"response_types_supported",
	"subject_types_supported",
	"id_token_signing_alg_values_supported",
] as const;

/**
 * Required fields whose value must be a non-empty array: present but empty,
 * or a scalar, they advertise metadata no relying party can use.
 */
const REQUIRED_NONEMPTY_ARRAY_FIELDS = [
	"subject_types_supported",
	"id_token_signing_alg_values_supported",
] as const;

/**
 * A response type is what a client asks for at the authorization endpoint, so
 * the document names the endpoint exactly when it lists a response type
 * (RFC 8414 §2). A server with no grant that uses the endpoint lists
 * `response_types_supported: []` — the field itself stays required — and
 * names none.
 */
function checkAuthorizationEndpoint(doc: Record<string, unknown>): void {
	const responseTypes = doc.response_types_supported;
	if (!Array.isArray(responseTypes)) {
		throw new DiscoveryDocumentError(
			"discovery document field response_types_supported must be an array (empty when no " +
				"grant uses the authorization endpoint)",
		);
	}
	const namesEndpoint = doc.authorization_endpoint !== undefined;
	if (namesEndpoint && responseTypes.length === 0) {
		throw new DiscoveryDocumentError(
			"discovery document names authorization_endpoint, so response_types_supported must be a " +
				"non-empty array: a client asks for a response type there",
		);
	}
	if (!namesEndpoint && responseTypes.length > 0) {
		throw new DiscoveryDocumentError(
			`discovery document lists response types (${JSON.stringify(responseTypes)}) but names no ` +
				"authorization_endpoint to ask for them at",
		);
	}
}

/**
 * Known issuer-relative endpoint field NAMES that do NOT end in `_endpoint`.
 * Endpoint fields must be contributed via `endpoints` (so they are issuer-
 * prefixed + absolute-path validated); contributing them via `metadata` would
 * emit an origin-less URL. The `_endpoint` suffix covers most OIDC endpoints
 * (`authorization_endpoint`, `registration_endpoint`, …); these are the
 * spec-defined exceptions that are issuer-relative URLs without that suffix.
 */
const ISSUER_RELATIVE_FIELD_NAMES = new Set(["jwks_uri", "check_session_iframe"]);

/**
 * Whether a `metadata` field looks like an issuer-relative endpoint that belongs
 * in `endpoints` instead. Catches it three ways so the guard does not rely on a
 * name allowlist alone: (a) the `_endpoint` suffix, (b) known non-suffixed
 * endpoint names, and — the general catch — (c) any VALUE that is a string
 * beginning with "/", which is issuer-relative by shape regardless of field
 * name. Literal metadata is booleans, capability arrays, or absolute external
 * URLs (`op_policy_uri: "https://…"`), none of which match, so they pass.
 */
function looksIssuerRelative(field: string, value: unknown): boolean {
	if (field.endsWith("_endpoint") || ISSUER_RELATIVE_FIELD_NAMES.has(field)) return true;
	return typeof value === "string" && value.startsWith("/");
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
 * Aggregate every module's {@link OidcDiscoveryContribution} into the single
 * OIDC discovery document, in module-registration order.
 *
 * The aggregator owns `issuer` and `id_token_signing_alg_values_supported`.
 * `endpoints` are prefixed with the issuer; `metadata` arrays are merged and
 * de-duplicated, scalars must agree.
 *
 * @throws {@link DiscoveryDocumentError} on any conflict or malformed
 * document, which fails the boot.
 */
export function buildDiscoveryDocument(
	items: readonly OidcDiscoveryContribution[],
	opts: { readonly issuer: string; readonly signingAlgs: readonly string[] },
): Record<string, unknown> {
	const issuer = opts.issuer.replace(/\/+$/, "");
	// An all-slashes issuer (e.g. "/", "//") passes `planDiscoveryDocument`'s own
	// gate (`issuer.length > 0`, on the RAW value) but normalizes to "" here,
	// which would emit `issuer: ""` and origin-less endpoint URLs. That is a
	// misconfiguration, so fail the boot fast rather than advertising a
	// malformed document.
	if (issuer === "") {
		throw new DiscoveryDocumentError(
			`discovery issuer must not be empty after trailing-slash normalization (got ${JSON.stringify(opts.issuer)})`,
		);
	}
	// `id_token_signing_alg_values_supported` is an OIDC-required field whose
	// emptiness the REQUIRED_FIELDS presence check cannot catch (the array is
	// present, just empty). An empty set advertises a document no RP can use to
	// verify id_tokens, so fail the boot fast rather than serving it. Empty here
	// signals `assembleApp` could not read a usable `keyStore.algorithm`.
	if (opts.signingAlgs.length === 0) {
		throw new DiscoveryDocumentError(
			"discovery document requires at least one id_token signing algorithm " +
				"(id_token_signing_alg_values_supported must be non-empty); none were derived from the keyStore",
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
			if (looksIssuerRelative(field, value)) {
				throw new DiscoveryDocumentError(
					`discoveryMetadata field "${field}" looks issuer-relative and must be contributed via ` +
						`\`endpoints\` (for absolute-path validation + issuer prefixing), not \`metadata\` ` +
						`(which is emitted literally and would advertise an origin-less URL)`,
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
			`discovery document is missing required field(s): ${missing.join(", ")}. ` +
				`Ensure every endpoint-owning module (e.g. the OAuth module and the JWKS module) is wired ` +
				`when an issuer is configured.`,
		);
	}

	checkAuthorizationEndpoint(doc);
	// Validity, not only presence: a scalar or `[]` passes the check above.
	const invalidArrays = REQUIRED_NONEMPTY_ARRAY_FIELDS.filter(
		(f) => !Array.isArray(doc[f]) || (doc[f] as unknown[]).length === 0,
	);
	if (invalidArrays.length > 0) {
		throw new DiscoveryDocumentError(
			`discovery document field(s) must be a non-empty array: ${invalidArrays.join(", ")}. ` +
				`A present-but-empty or non-array value is advertised as OIDC-invalid metadata.`,
		);
	}

	return doc;
}
