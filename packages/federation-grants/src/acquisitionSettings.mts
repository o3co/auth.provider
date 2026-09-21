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
 * What a deployment must have configured before it may create grants (#593
 * slice 6, D6–D8), resolved once, at boot.
 *
 * Every refusal here is one a user would otherwise meet at the end of a
 * consent — standing in front of a page that cannot be shown, or coming back
 * from the upstream to a callback that was never going to accept them. Those
 * are the worst places to find out a deployment was not set up to finish what
 * it started, so they are found out here.
 */

import type {
	FederationGrantAcquisitionConnection,
	FederationGrantConnection,
	FederationGrantIntentStore,
} from "@o3co/auth-provider-core";

/** Where the connect flow's callback route lives under the provider's origin. */
export const FEDERATION_GRANT_CALLBACK_PATH = "/session/federation-grants/callback/";

export type FederationGrantIdentityLookup = "required" | "unsupported";

export interface FederationGrantAcquisitionSettings {
	/** The deployment's consent page, as configured: a path, or an absolute URL on {@link origin}. */
	readonly consentUrl: string;
	readonly identityLookup: FederationGrantIdentityLookup;
	/** The provider's browser-facing origin — the issuer's — never a request header. */
	readonly origin: string;
	/** Every configured connection, each with the callback its flow returns to. */
	readonly connections: ReadonlyMap<string, FederationGrantAcquisitionConnection>;
}

const refuse = (message: string): never => {
	throw new Error(`federationGrantsModule: ${message}`);
};

const issuerOrigin = (config: unknown): string => {
	const issuer = (config as { oauth?: { jwt?: { issuer?: unknown } } })?.oauth?.jwt?.issuer;
	if (typeof issuer !== "string") return refuse("oauth.jwt.issuer must be configured");
	try {
		return new URL(issuer).origin;
	} catch {
		return refuse(`oauth.jwt.issuer must be an absolute URL, and ${JSON.stringify(issuer)} is not`);
	}
};

/**
 * The consent page. No default, unlike `endpoints.consent.url`: enabling
 * grants is a recorded statement that a page exists (D8).
 *
 * A path, or an absolute URL on the provider's own origin, and nothing else.
 * The page reads what it must show with the session cookie, and this provider
 * never answers a credentialed cross-origin read (`middleware/cors.mts`) — so a
 * page on another origin could never show the user the client, the expiry, or
 * that the access outlives logout, and consent without those is not D8's.
 */
const consentUrl = (config: unknown, origin: string): string => {
	const written = (config as { federationGrants?: { consent?: { url?: unknown } } })
		?.federationGrants?.consent?.url;
	if (typeof written !== "string" || written === "") {
		return refuse(
			"federationGrants.consent.url must name the deployment's consent page. The provider ships " +
				"no UI, a grant is never created without the user's consent, and there is no default: " +
				"enabling federation grants is a statement that such a page exists (D8)",
		);
	}
	if (written.startsWith("/") && !written.startsWith("//")) {
		if (written.includes("#"))
			return refuse("federationGrants.consent.url must not carry a fragment");
		// A path has to STAY a path once resolved: `/.//evil.example/consent`
		// normalises to `//evil.example/consent`, which a browser reads as another
		// host. Resolved against the provider's origin, it must still be on it.
		const resolved = new URL(written, origin);
		if (resolved.origin !== origin || resolved.pathname.startsWith("//")) {
			return refuse(
				`federationGrants.consent.url ${JSON.stringify(written)} does not stay on the provider's ` +
					"own origin once resolved",
			);
		}
		return written;
	}
	let url: URL;
	try {
		url = new URL(written);
	} catch {
		return refuse(
			`federationGrants.consent.url must be a path or an absolute URL, and ${JSON.stringify(written)} is neither`,
		);
	}
	if (
		url.origin !== origin ||
		written.includes("#") ||
		url.username !== "" ||
		url.password !== ""
	) {
		return refuse(
			`federationGrants.consent.url must be on the provider's own origin (${origin}), without a ` +
				"fragment or credentials: the page reads the consent data with the session cookie, and " +
				"this provider never allows a credentialed cross-origin read",
		);
	}
	return written;
};

const identityLookup = (config: unknown): FederationGrantIdentityLookup => {
	const written = (config as { federationGrants?: { identityLookup?: unknown } })?.federationGrants
		?.identityLookup;
	if (written === undefined) return "required";
	if (written === "required" || written === "unsupported") return written;
	return refuse(
		`federationGrants.identityLookup must be "required" or "unsupported", and was ${JSON.stringify(written)}`,
	);
};

/**
 * A connection's callback: on the provider's origin, at the acquisition route
 * for THIS connection, with no query. A deployment behind a path prefix keeps
 * the prefix in front of the route.
 *
 * Absent is refused rather than defaulted to the federation's login callback:
 * a code landing there would be handled as a login.
 */
const acquisitionConnection = (
	connection: FederationGrantConnection,
	origin: string,
): FederationGrantAcquisitionConnection => {
	const key = `federationGrants.connections.${connection.name}.callbackURL`;
	const written = connection.callbackUri;
	if (written === undefined) {
		return refuse(
			`${key} must be configured: it is where the upstream returns the browser at the end of a ` +
				`connect flow, ${origin}<prefix>${FEDERATION_GRANT_CALLBACK_PATH}${connection.name}. There is ` +
				"no fallback to the federation's login callback, which would treat the code as a login",
		);
	}
	const url = new URL(written);
	const route = `${FEDERATION_GRANT_CALLBACK_PATH}${encodeURIComponent(connection.name)}`;
	if (url.origin !== origin || url.search !== "" || !url.pathname.endsWith(route)) {
		return refuse(
			`${key} must be on the provider's own origin (${origin}), end in ${route}, and carry no ` +
				`query — and was ${JSON.stringify(written)}`,
		);
	}
	return { ...connection, callbackUri: written };
};

export function resolveFederationGrantAcquisitionSettings(
	config: unknown,
	connections: ReadonlyMap<string, FederationGrantConnection>,
): FederationGrantAcquisitionSettings {
	const origin = issuerOrigin(config);
	const settings: FederationGrantAcquisitionSettings = {
		consentUrl: consentUrl(config, origin),
		identityLookup: identityLookup(config),
		origin,
		connections: new Map(
			[...connections.values()].map((entry) => [entry.name, acquisitionConnection(entry, origin)]),
		),
	};
	return settings;
}

/**
 * D7 check 5 asks whether the upstream identity is already another local
 * user's, which needs a lookup the Store port has only optionally. `"required"`
 * — the default — refuses to boot without it; `"unsupported"` is the recorded
 * decision to skip that one check, and it is recorded in the audit of every
 * acquisition rather than taken silently.
 */
export function requireFederationGrantIdentityLookup(
	mode: FederationGrantIdentityLookup,
	userRepository: { readonly findSubjectByFederatedIdentity?: unknown } | undefined,
): void {
	if (mode === "unsupported") return;
	if (typeof userRepository?.findSubjectByFederatedIdentity !== "function") {
		refuse(
			'federationGrants.identityLookup is "required" (the default), and the userRepository has no ' +
				"findSubjectByFederatedIdentity. Implement it — side-effect-free, answering the local user " +
				'an upstream identity is linked to — or set identityLookup = "unsupported" to record that ' +
				"this deployment does not refuse an upstream account already linked to another user",
		);
	}
}

export function requireFederationGrantIntentStore(
	store: FederationGrantIntentStore | undefined,
): FederationGrantIntentStore {
	if (store === undefined) {
		return refuse(
			"federation grants are enabled and no federationGrantIntentStore is installed. A grant is " +
				"created through an intent a client lodges, a consent the user answers and a transaction " +
				"the callback consumes; install memoryFederationGrantIntentStoreModule (one replica) or " +
				"redisFederationGrantIntentStoreModule",
		);
	}
	return store;
}
