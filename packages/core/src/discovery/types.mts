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
 * A partial OIDC discovery document contributed by an endpoint-owning module
 * (oauth, jwks, future PAR / device-authorization, …). Core's boot planner
 * aggregates every module's `discoveryMetadata` contribution into the single
 * `/.well-known/openid-configuration` document via `buildDiscoveryDocument`.
 *
 * Splitting `endpoints` (issuer-relative paths the aggregator prefixes) from
 * `metadata` (literal fields) lets the aggregator own issuer-relative URL
 * construction while modules stay agnostic of the deployment's issuer origin.
 */
export interface OidcDiscoveryContribution {
	/**
	 * Marks this contribution as activating an OpenID Provider / OAuth
	 * authorization-server surface — i.e. "a discovery document SHOULD be served
	 * here." Core emits `/.well-known/openid-configuration` only when an issuer is
	 * configured AND at least one contribution sets this. This is an EXPLICIT
	 * activation signal: an ancillary contributor (e.g. the JWKS module, which
	 * only adds `jwks_uri`) leaves it unset, so a key-publishing deployment can
	 * mount JWKS without being treated as a provider. The module that owns the
	 * authorization-server surface (oauth, or a future CIBA / device-flow module)
	 * sets it — so providers that do not expose `authorization_endpoint` still
	 * activate discovery instead of silently serving nothing.
	 */
	readonly providerRoot?: boolean;
	/**
	 * Endpoint paths RELATIVE to the issuer identifier. The aggregator emits
	 * `${issuer}${path}` under the given discovery field name (e.g.
	 * `authorization_endpoint`, `jwks_uri`). Each path MUST be absolute
	 * (begin with "/"). Two modules contributing the same field must resolve
	 * to the same URL, else boot fails.
	 */
	readonly endpoints?: { readonly [field: string]: string };
	/**
	 * Literal discovery fields merged as-is — booleans, capability arrays,
	 * absolute external URLs (`op_policy_uri`, …). Array values are concatenated
	 * and de-duplicated across contributions (first-seen order preserved); scalar
	 * values from two contributions must agree, else boot fails.
	 *
	 * This bucket is for LITERAL fields ONLY. An issuer-relative endpoint placed
	 * here would be emitted verbatim (no issuer prefix, no absolute-path check) —
	 * an origin-less URL — so the aggregator rejects values that look
	 * issuer-relative (a string beginning with "/") and known endpoint field
	 * names; contribute those via `endpoints` instead. Must NOT carry a reserved
	 * field (`issuer`, `id_token_signing_alg_values_supported`) — the aggregator
	 * owns those — nor a field already provided via `endpoints`.
	 */
	readonly metadata?: { readonly [field: string]: unknown };
}
