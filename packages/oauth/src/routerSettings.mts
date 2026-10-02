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
 * What the `/oauth` router resolves once, when it is built, and hands its
 * endpoints: the `oauth.*` options, the acr table `/authorize` answers from,
 * the canonical issuer (one that is not canonical refuses the build) and the
 * one client repository every endpoint looks a client up in.
 */

import {
	type AppConfig,
	advertisedIssuer,
	type ClientRepository,
	type ConsentStore,
	checkCanonicalIssuer,
	describeIssuerRejection,
	type FederationProvider,
	type Logger,
	type SessionRequirementResolver,
	stepUpReach,
} from "@o3co/auth-provider-core";
import { logUnsatisfiableAcrValues, vouchableAcrValues } from "./acrValues.mjs";
import { behindClientBoundary } from "./clients/clientBoundary.mjs";
import {
	type ClientIdMetadataDocumentOptions,
	withClientIdMetadataDocuments,
} from "./clients/clientIdMetadataDocument.mjs";
import { type ResolvedOAuthOptions, resolveOAuthOptions } from "./resolveOAuthOptions.mjs";
import {
	type AuthorizationResponse,
	authorizationResponseFor,
} from "./routes/authorizationResponse.mjs";

/** What {@link resolveRouterSettings} resolved. */
export interface RouterSettings {
	readonly options: ResolvedOAuthOptions;
	/** Undefined when `/authorize` is not mounted. */
	readonly acrTable: ReturnType<typeof vouchableAcrValues>["table"] | undefined;
	readonly canonicalIssuer: string;
	/** Builds every authorization response, its `iss` (RFC 9207) bound to `advertisedIssuer(canonicalIssuer)`. */
	readonly authorizationResponse: AuthorizationResponse;
	readonly clientRepository: ClientRepository;
}

export const resolveRouterSettings = ({
	config,
	authorizationEndpoint,
	requirements,
	getFederationProviders,
	registeredClients,
	consentStore,
	clientIdMetadataDocumentSeams,
	logger,
}: {
	readonly config: AppConfig;
	/** Whether `/authorize` is mounted. */
	readonly authorizationEndpoint: boolean;
	readonly requirements: SessionRequirementResolver;
	readonly getFederationProviders: () => ReadonlyMap<string, FederationProvider> | undefined;
	readonly registeredClients: ClientRepository;
	readonly consentStore: ConsentStore | undefined;
	readonly clientIdMetadataDocumentSeams: Pick<
		ClientIdMetadataDocumentOptions,
		"fetch" | "lookup" | "now"
	>;
	readonly logger: Logger;
}): RouterSettings => {
	// Every `oauth.*` knob this router consumes is resolved exactly once,
	// here, at router composition; see `resolveOAuthOptions` for the defensive
	// reads and per-field defaults. The /authorize handler receives the whole
	// object (routes/authorize.mts).
	const options = resolveOAuthOptions(config);
	// `/authorize` answers `acr_values` only from the entries this composition
	// can satisfy — the same table discovery advertises — and an entry dropped
	// is said once, here, at composition. With no `/authorize` there is no
	// table to answer from, and nothing to say. What the registered
	// requirements can add to a session by a step-up is read once here, after
	// every name-keyed contribution registered.
	let acrTable: ReturnType<typeof vouchableAcrValues>["table"] | undefined;
	if (authorizationEndpoint) {
		const reach = stepUpReach(Array.from(requirements.entries(), ([, r]) => r));
		const acrValues = vouchableAcrValues(
			options.acrValues,
			getFederationProviders(),
			config,
			reach,
		);
		logUnsatisfiableAcrValues(acrValues.dropped, reach, logger);
		acrTable = acrValues.table;
	}
	// `iss` is a property of the deployment, never of a request: a fallback to
	// the `Host` header would let a caller choose the issuer of its tokens. A
	// canonical issuer is required and is the only source, resolved once here
	// so no request path can reach a fallback. It also populates the `realm`
	// parameter on `WWW-Authenticate: Basic` challenges (RFC 7235 §2.2).
	const issuerRejection = checkCanonicalIssuer(options.issuer);
	if (issuerRejection) {
		throw new Error(
			`createOAuthRouter: oauth.jwt.issuer ${describeIssuerRejection(issuerRejection)}`,
		);
	}
	// `checkCanonicalIssuer` returned null above, which only a string satisfies.
	const canonicalIssuer = options.issuer as string;
	// Every endpoint reads clients through core's client-record boundary,
	// outermost over the repository it was handed (`behindClientBoundary`).
	//
	// Client ID Metadata Documents. Pre-registered clients answer first; a
	// client_id that is an https URL is then resolved from the document it
	// names, under the operator's ceilings, only when no client is registered
	// under it (`withClientIdMetadataDocuments`, over the boundary itself). One repository for every endpoint
	// the router mounts — /authorize, /token, /revoke — so a document client is
	// the same client everywhere.
	//
	// Wired only with a consent store and the authorization_code grant, the
	// gate discovery applies: a document client is never first-party, so
	// `/authorize` refuses it without a consent store, and it may use no other
	// grant. Resolving it anyway would make each request a guarded outbound
	// HTTPS fetch before the refusal — an amplification surface where no
	// request can succeed.
	const cimd = options.clientIdMetadataDocuments;
	const clientRepository: ClientRepository =
		cimd.enabled && consentStore !== undefined && authorizationEndpoint
			? withClientIdMetadataDocuments(registeredClients, {
					allowedScopes: cimd.allowedScopes,
					allowedAudiences: cimd.allowedAudiences,
					allowedHosts: cimd.allowedHosts,
					deniedHosts: cimd.deniedHosts,
					...(cimd.maxBytes === undefined ? {} : { maxBytes: cimd.maxBytes }),
					...(cimd.timeoutMs === undefined ? {} : { timeoutMs: cimd.timeoutMs }),
					...(cimd.cacheMaxAgeMs === undefined ? {} : { cacheMaxAgeMs: cimd.cacheMaxAgeMs }),
					...(cimd.maxCacheEntries === undefined ? {} : { maxCacheEntries: cimd.maxCacheEntries }),
					...(cimd.staleIfErrorMs === undefined ? {} : { staleIfErrorMs: cimd.staleIfErrorMs }),
					...(cimd.negativeCacheMs === undefined ? {} : { negativeCacheMs: cimd.negativeCacheMs }),
					...(cimd.maxConcurrentFetches === undefined
						? {}
						: { maxConcurrentFetches: cimd.maxConcurrentFetches }),
					logger,
					...clientIdMetadataDocumentSeams,
				})
			: behindClientBoundary(registeredClients, logger);
	return {
		options,
		acrTable,
		canonicalIssuer,
		authorizationResponse: authorizationResponseFor(advertisedIssuer(canonicalIssuer)),
		clientRepository,
	};
};
