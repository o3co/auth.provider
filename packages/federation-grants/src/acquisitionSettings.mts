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
 * What a deployment must have configured before it may create grants,
 * resolved once, at boot. Every refusal here is one a user would otherwise
 * meet at the end of a consent: a page that cannot be shown, or a callback
 * that was never going to accept them. The design record is
 * `packages/core/docs/adr/2026-09-17-federation-grants-offline-delegation.md`.
 */

import type {
	FederatedIdentityRegistration,
	FederationGrantAcquisitionConnection,
	FederationGrantConnection,
	FederationGrantIntentStore,
	LoginEntry,
	UserRepository,
} from "@o3co/auth-provider-core";

/** Where the connect flow's callback route lives under the provider's origin. */
export const FEDERATION_GRANT_CALLBACK_PATH = "/session/federation-grants/callback/";

export type FederationGrantIdentityLookup = "required" | "unsupported";

export interface FederationGrantAcquisitionSettings {
	/** The deployment's consent page, as configured: a path, or an absolute URL on {@link origin}. */
	readonly consentUrl: string;
	/**
	 * Where connect sends a browser that is not signed in, and how it comes
	 * back: the `loginEntry` slot the session module provides.
	 */
	readonly login: LoginEntry;
	readonly identityLookup: FederationGrantIdentityLookup;
	/** The provider's browser-facing origin — the issuer's — never a request header. */
	readonly origin: string;
	/** Every configured connection, each with the callback its flow returns to. */
	readonly connections: ReadonlyMap<string, FederationGrantAcquisitionConnection>;
}

const refuse = (message: string, options?: ErrorOptions): never => {
	throw new Error(`federationGrantsModule: ${message}`, options);
};

/**
 * The provider's browser-facing origin: the issuer's, as the caller hands it —
 * the `oauthTokenSettings` slot's, or `oauth.jwt.issuer` as the configuration
 * carries it.
 */
const issuerOrigin = (issuer: unknown): string => {
	if (typeof issuer !== "string") return refuse("oauth.jwt.issuer must be configured");
	try {
		return new URL(issuer).origin;
	} catch {
		return refuse(`oauth.jwt.issuer must be an absolute URL, and ${JSON.stringify(issuer)} is not`);
	}
};

/**
 * The consent page: no default, unlike the oauth module's consent page, because
 * enabling grants is a recorded statement that a page exists. A path, or an
 * absolute URL on the provider's own origin, and nothing else: the page reads
 * what it must show with the session cookie, and this provider never answers
 * a credentialed cross-origin read (`middleware/cors.mts`), so a page on
 * another origin could not show the user the client, the expiry, or that the
 * access outlives logout.
 */
const consentUrl = (section: AcquisitionSection | undefined, origin: string): string => {
	const written = section?.consent?.url;
	if (typeof written !== "string" || written === "") {
		return refuse(
			"federation-grants.consent.url must name the deployment's consent page. The provider ships " +
				"no UI, a grant is never created without the user's consent, and there is no default: " +
				"enabling federation grants is a statement that such a page exists",
		);
	}
	if (written.startsWith("/") && !written.startsWith("//")) {
		if (written.includes("#"))
			return refuse("federation-grants.consent.url must not carry a fragment");
		// A path has to STAY a path once resolved: `/.//evil.example/consent`
		// normalises to `//evil.example/consent`, which a browser reads as another
		// host. Resolved against the provider's origin, it must still be on it.
		const resolved = new URL(written, origin);
		if (resolved.origin !== origin || resolved.pathname.startsWith("//")) {
			return refuse(
				`federation-grants.consent.url ${JSON.stringify(written)} does not stay on the provider's ` +
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
			`federation-grants.consent.url must be a path or an absolute URL, and ${JSON.stringify(written)} is neither`,
		);
	}
	if (
		url.origin !== origin ||
		written.includes("#") ||
		url.username !== "" ||
		url.password !== ""
	) {
		return refuse(
			`federation-grants.consent.url must be on the provider's own origin (${origin}), without a ` +
				"fragment or credentials: the page reads the consent data with the session cookie, and " +
				"this provider never allows a credentialed cross-origin read",
		);
	}
	return written;
};

/**
 * The login page connect sends a browser that is not signed in to: the
 * `loginEntry` slot, which the session module provides. Optional in the
 * manifest, so a deployment that leaves grants off owes nothing; required
 * here, once they are on.
 *
 * An entry built with no page configured fails where its `url` is read: here,
 * at boot, rather than answering every such browser with a 500.
 */
const loginEntry = (entry: LoginEntry | undefined): LoginEntry => {
	if (entry === undefined) {
		return refuse(
			"federation grants are enabled and no loginEntry is installed. The connect flow sends a " +
				"browser that is not signed in to the login page, and back to the link it came from, " +
				"through the loginEntry slot the session module (sessionModule) provides",
		);
	}
	try {
		void entry.url;
	} catch (error) {
		return refuse(
			"the loginEntry slot names no login page: the connect flow sends a browser that is not " +
				"signed in to the login page, and back to the link it came from",
			{ cause: error },
		);
	}
	return entry;
};

const identityLookup = (section: AcquisitionSection | undefined): FederationGrantIdentityLookup => {
	const written = section?.identityLookup;
	if (written === undefined) return "required";
	if (written === "required" || written === "unsupported") return written;
	return refuse(
		`federation-grants.identityLookup must be "required" or "unsupported", and was ${JSON.stringify(written)}`,
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
	const key = `federation-grants.connections.${connection.name}.callbackURL`;
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

/** What acquisition reads of `federation-grants {}`, each as written. */
interface AcquisitionSection {
	readonly consent?: { readonly url?: unknown };
	readonly identityLookup?: unknown;
}

/**
 * What creating a grant needs, from `section` (`federation-grants {}`): the
 * consent page and the identity lookup; the connections, each with its
 * callback; the login page; and the provider's origin, off `options.issuer`.
 */
export function resolveFederationGrantAcquisitionSettings(
	section: AcquisitionSection | undefined,
	connections: ReadonlyMap<string, FederationGrantConnection>,
	login: LoginEntry | undefined,
	/** The issuer the routes are built on: the `oauthTokenSettings` slot's, or the configuration's. */
	options: { readonly issuer?: unknown } = {},
): FederationGrantAcquisitionSettings {
	const origin = issuerOrigin(options.issuer);
	const settings: FederationGrantAcquisitionSettings = {
		consentUrl: consentUrl(section, origin),
		login: loginEntry(login),
		identityLookup: identityLookup(section),
		origin,
		connections: new Map(
			[...connections.values()].map((entry) => [entry.name, acquisitionConnection(entry, origin)]),
		),
	};
	return settings;
}

/**
 * The registration an identity arriving through `connection` was issued
 * under, as the Store is asked about it — at boot, whether it covers
 * it, and in the callback, who holds an identity from it. Configuration only:
 * the federation's name, its configured issuer and the client it was issued to.
 */
export function federationGrantIdentityRegistration(
	connection: Pick<FederationGrantConnection, "federation" | "upstreamIssuer" | "upstreamClientId">,
): FederatedIdentityRegistration {
	return {
		provider: connection.federation,
		issuer: connection.upstreamIssuer,
		clientId: connection.upstreamClientId,
	};
}

const IDENTITY_LOOKUP_REMEDY =
	'install a userRepository that covers it, or set federation-grants.identityLookup = "unsupported" ' +
	"to record that this deployment does not refuse an upstream account already linked to another user";

/**
 * Acquisition asks whether the upstream identity is already another local
 * user's, which needs a lookup the
 * Store port has only optionally. `"required"` — the default — refuses to
 * boot without it; `"unsupported"` is the decision to skip that one check,
 * recorded in the audit of every acquisition rather than taken silently.
 *
 * Having the method is not enough: a lookup that sees only the namespace it
 * is handed answers "linked to nobody" for an identity from a registration
 * no login linked under (a dedicated registration, whose pairwise `sub` no
 * login ever saw). So the Store says, per connection's registration, whether
 * it covers it, and anything but a literal `true` is refused here.
 */
export function requireFederationGrantIdentityLookup(
	mode: FederationGrantIdentityLookup,
	userRepository:
		| Partial<
				Pick<UserRepository, "findSubjectByFederatedIdentity" | "supportsFederatedIdentityLookup">
		  >
		| undefined,
	connections: ReadonlyMap<string, FederationGrantConnection>,
): void {
	// Nothing can reach check 5 without a connection, so nothing is required —
	// not even the methods: removing the last connection must stay operable
	// for a repository that has no lookup at all.
	if (mode === "unsupported" || connections.size === 0) return;
	if (typeof userRepository?.findSubjectByFederatedIdentity !== "function") {
		refuse(
			'federation-grants.identityLookup is "required" (the default), and the userRepository has no ' +
				"findSubjectByFederatedIdentity. Implement it — side-effect-free, answering who holds an " +
				'upstream identity across every registration — or set identityLookup = "unsupported" to ' +
				"record that this deployment does not refuse an upstream account already linked to another user",
		);
	}
	if (typeof userRepository?.supportsFederatedIdentityLookup !== "function") {
		refuse(
			'federation-grants.identityLookup is "required" (the default), and the userRepository has no ' +
				"supportsFederatedIdentityLookup: it cannot say which upstream registrations its lookup " +
				"covers, so a lookup that sees only the name and sub it is handed would read an account " +
				`another user holds as linked to nobody. Implement it, or ${IDENTITY_LOOKUP_REMEDY}`,
		);
	}
	const repository = userRepository as Pick<UserRepository, "supportsFederatedIdentityLookup">;
	for (const connection of connections.values()) {
		const registration = federationGrantIdentityRegistration(connection);
		let covered: unknown;
		let threw = false;
		try {
			// Through the repository, never detached: a Store written as a class reads its own fields.
			covered = repository.supportsFederatedIdentityLookup?.(
				registration,
				connection.identityClaims ?? [],
			);
		} catch {
			// Not the error itself: a Store's message may carry what it was connected with.
			threw = true;
		}
		if (covered !== true) {
			// A probe written as `async` answers a promise: not `true`, so refused
			// — and if it rejects, nothing else would ever observe that, and the
			// host would see an unhandled rejection beside the refusal.
			if (typeof (covered as { then?: unknown } | null)?.then === "function") {
				(covered as PromiseLike<unknown>).then(undefined, () => undefined);
			}
			refuse(
				`federation-grants.connections.${connection.name}: the userRepository ` +
					(threw ? "threw when asked whether it covers" : "does not cover") +
					` the registration its identities are issued under (federation "${registration.provider}", ` +
					`issuer ${registration.issuer}, client ${registration.clientId}, identityClaims ` +
					`${JSON.stringify(connection.identityClaims ?? [])}), so it could not tell an ` +
					"upstream account linked to nobody from one another user holds through another " +
					`registration. Remove the connection, ${IDENTITY_LOOKUP_REMEDY}`,
			);
		}
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
