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
/** Where the connect flow's callback route lives under the provider's origin. */
export const FEDERATION_GRANT_CALLBACK_PATH = "/session/federation-grants/callback/";
const refuse = (message) => {
    throw new Error(`federationGrantsModule: ${message}`);
};
const issuerOrigin = (config) => {
    const issuer = config?.oauth?.jwt?.issuer;
    if (typeof issuer !== "string")
        return refuse("oauth.jwt.issuer must be configured");
    try {
        return new URL(issuer).origin;
    }
    catch {
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
const consentUrl = (config, origin) => {
    const written = config
        ?.federationGrants?.consent?.url;
    if (typeof written !== "string" || written === "") {
        return refuse("federationGrants.consent.url must name the deployment's consent page. The provider ships " +
            "no UI, a grant is never created without the user's consent, and there is no default: " +
            "enabling federation grants is a statement that such a page exists (D8)");
    }
    if (written.startsWith("/") && !written.startsWith("//")) {
        if (written.includes("#"))
            return refuse("federationGrants.consent.url must not carry a fragment");
        // A path has to STAY a path once resolved: `/.//evil.example/consent`
        // normalises to `//evil.example/consent`, which a browser reads as another
        // host. Resolved against the provider's origin, it must still be on it.
        const resolved = new URL(written, origin);
        if (resolved.origin !== origin || resolved.pathname.startsWith("//")) {
            return refuse(`federationGrants.consent.url ${JSON.stringify(written)} does not stay on the provider's ` +
                "own origin once resolved");
        }
        return written;
    }
    let url;
    try {
        url = new URL(written);
    }
    catch {
        return refuse(`federationGrants.consent.url must be a path or an absolute URL, and ${JSON.stringify(written)} is neither`);
    }
    if (url.origin !== origin ||
        written.includes("#") ||
        url.username !== "" ||
        url.password !== "") {
        return refuse(`federationGrants.consent.url must be on the provider's own origin (${origin}), without a ` +
            "fragment or credentials: the page reads the consent data with the session cookie, and " +
            "this provider never allows a credentialed cross-origin read");
    }
    return written;
};
/**
 * The login page connect sends a browser that is not signed in to. Core's
 * schema leaves `endpoints.login.url` optional and only `oauthModule` requires
 * it, so a deployment that enables grants without that module would boot and
 * then answer every such browser with a 500 — the first page of the flow, and
 * the one a user reaches most often.
 */
const loginUrl = (config) => {
    const written = config?.endpoints?.login?.url;
    if (typeof written !== "string" || written === "") {
        return refuse("endpoints.login.url must be configured: the connect flow sends a browser that is not " +
            "signed in to the login page, and back to the link it came from");
    }
    return written;
};
const identityLookup = (config) => {
    const written = config?.federationGrants
        ?.identityLookup;
    if (written === undefined)
        return "required";
    if (written === "required" || written === "unsupported")
        return written;
    return refuse(`federationGrants.identityLookup must be "required" or "unsupported", and was ${JSON.stringify(written)}`);
};
/**
 * A connection's callback: on the provider's origin, at the acquisition route
 * for THIS connection, with no query. A deployment behind a path prefix keeps
 * the prefix in front of the route.
 *
 * Absent is refused rather than defaulted to the federation's login callback:
 * a code landing there would be handled as a login.
 */
const acquisitionConnection = (connection, origin) => {
    const key = `federationGrants.connections.${connection.name}.callbackURL`;
    const written = connection.callbackUri;
    if (written === undefined) {
        return refuse(`${key} must be configured: it is where the upstream returns the browser at the end of a ` +
            `connect flow, ${origin}<prefix>${FEDERATION_GRANT_CALLBACK_PATH}${connection.name}. There is ` +
            "no fallback to the federation's login callback, which would treat the code as a login");
    }
    const url = new URL(written);
    const route = `${FEDERATION_GRANT_CALLBACK_PATH}${encodeURIComponent(connection.name)}`;
    if (url.origin !== origin || url.search !== "" || !url.pathname.endsWith(route)) {
        return refuse(`${key} must be on the provider's own origin (${origin}), end in ${route}, and carry no ` +
            `query — and was ${JSON.stringify(written)}`);
    }
    return { ...connection, callbackUri: written };
};
export function resolveFederationGrantAcquisitionSettings(config, connections) {
    const origin = issuerOrigin(config);
    const settings = {
        consentUrl: consentUrl(config, origin),
        loginUrl: loginUrl(config),
        identityLookup: identityLookup(config),
        origin,
        connections: new Map([...connections.values()].map((entry) => [entry.name, acquisitionConnection(entry, origin)])),
    };
    return settings;
}
/**
 * The registration an identity arriving through `connection` was issued
 * under, as the Store is asked about it (#611) — at boot, whether it covers
 * it, and in the callback, who holds an identity from it. Configuration only:
 * the federation's name, its configured issuer and the client it was issued to.
 */
export function federationGrantIdentityRegistration(connection) {
    return {
        provider: connection.federation,
        issuer: connection.upstreamIssuer,
        clientId: connection.upstreamClientId,
    };
}
const IDENTITY_LOOKUP_REMEDY = 'install a userRepository that covers it, or set federationGrants.identityLookup = "unsupported" ' +
    "to record that this deployment does not refuse an upstream account already linked to another user";
/**
 * D7 check 5 asks whether the upstream identity is already another local
 * user's, which needs a lookup the Store port has only optionally. `"required"`
 * — the default — refuses to boot without it; `"unsupported"` is the recorded
 * decision to skip that one check, and it is recorded in the audit of every
 * acquisition rather than taken silently.
 *
 * #611: having the method is not enough. A lookup that can see only the
 * namespace it is handed answers "linked to nobody" for an identity from a
 * registration no login linked under — D19's dedicated registration, whose
 * pairwise `sub` no login ever saw — and `"required"` would be satisfied by a
 * check that cannot see the answer. So the Store says, per connection's
 * registration, whether it covers it, and anything but a literal `true` is
 * refused here rather than met by every user who connects. With no connection
 * configured nothing is required, not even the methods: removing the last one
 * must stay operable on any repository.
 */
export function requireFederationGrantIdentityLookup(mode, userRepository, connections) {
    // Nothing can reach check 5 without a connection, so nothing is required —
    // not even the methods: removing the last connection must stay operable
    // for a repository that has no lookup at all (Copilot, #612).
    if (mode === "unsupported" || connections.size === 0)
        return;
    if (typeof userRepository?.findSubjectByFederatedIdentity !== "function") {
        refuse('federationGrants.identityLookup is "required" (the default), and the userRepository has no ' +
            "findSubjectByFederatedIdentity. Implement it — side-effect-free, answering who holds an " +
            'upstream identity across every registration — or set identityLookup = "unsupported" to ' +
            "record that this deployment does not refuse an upstream account already linked to another user");
    }
    if (typeof userRepository?.supportsFederatedIdentityLookup !== "function") {
        refuse('federationGrants.identityLookup is "required" (the default), and the userRepository has no ' +
            "supportsFederatedIdentityLookup: it cannot say which upstream registrations its lookup " +
            "covers, so a lookup that sees only the name and sub it is handed would read an account " +
            `another user holds as linked to nobody. Implement it, or ${IDENTITY_LOOKUP_REMEDY}`);
    }
    const repository = userRepository;
    for (const connection of connections.values()) {
        const registration = federationGrantIdentityRegistration(connection);
        let covered;
        let threw = false;
        try {
            // Through the repository, never detached: a Store written as a class reads its own fields.
            covered = repository.supportsFederatedIdentityLookup?.(registration, connection.identityClaims ?? []);
        }
        catch {
            // Not the error itself: a Store's message may carry what it was connected with.
            threw = true;
        }
        if (covered !== true) {
            // A probe written as `async` answers a promise: not `true`, so refused
            // — and if it rejects, nothing else would ever observe that, and the
            // host would see an unhandled rejection beside the refusal (Copilot).
            if (typeof covered?.then === "function") {
                covered.then(undefined, () => undefined);
            }
            refuse(`federationGrants.connections.${connection.name}: the userRepository ` +
                (threw ? "threw when asked whether it covers" : "does not cover") +
                ` the registration its identities are issued under (federation "${registration.provider}", ` +
                `issuer ${registration.issuer}, client ${registration.clientId}, identityClaims ` +
                `${JSON.stringify(connection.identityClaims ?? [])}), so it could not tell an ` +
                "upstream account linked to nobody from one another user holds through another " +
                `registration. Remove the connection, ${IDENTITY_LOOKUP_REMEDY}`);
        }
    }
}
export function requireFederationGrantIntentStore(store) {
    if (store === undefined) {
        return refuse("federation grants are enabled and no federationGrantIntentStore is installed. A grant is " +
            "created through an intent a client lodges, a consent the user answers and a transaction " +
            "the callback consumes; install memoryFederationGrantIntentStoreModule (one replica) or " +
            "redisFederationGrantIntentStoreModule");
    }
    return store;
}
