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
 * A partial OIDC discovery document contributed by an endpoint-owning module.
 * `buildDiscoveryDocument` aggregates every contribution into
 * `/.well-known/openid-configuration`. `endpoints` are issuer-relative so
 * modules never need to know the issuer origin.
 */
export interface OidcDiscoveryContribution {
	/**
	 * Set by the module that owns an authorization-server surface. Discovery
	 * is served only when an issuer is configured AND some contribution sets
	 * this. Ancillary contributors (e.g. JWKS, which only adds `jwks_uri`)
	 * leave it unset, so mounting JWKS alone does not make a provider.
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
	 * Literal discovery fields merged as-is: booleans, capability arrays,
	 * absolute external URLs. Arrays are concatenated and de-duplicated in
	 * first-seen order; scalars from two contributions must agree, else boot
	 * fails.
	 *
	 * LITERAL fields only: anything that looks issuer-relative (a value
	 * starting with "/", or a known endpoint name) is rejected and belongs in
	 * `endpoints`. Must NOT carry `issuer` or
	 * `id_token_signing_alg_values_supported`, which the aggregator owns.
	 */
	readonly metadata?: { readonly [field: string]: unknown };
}
