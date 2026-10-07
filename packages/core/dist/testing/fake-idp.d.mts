/**
 * A fake OpenID Provider behind a `fetch` implementation (#542).
 *
 * The provider under test is handed `idp.fetch` through its `fetch` option,
 * which openid-client uses for every request it makes — discovery, JWKS,
 * token, userinfo — so nothing here touches the network and every request is
 * recorded for the tests to inspect. The IdP signs real RS256 id_tokens under
 * a key it publishes at its JWKS URI; the knobs below let a test make it
 * misbehave in exactly one way at a time.
 *
 * One harness for the OpenID Connect adapters — Google, Apple and the generic
 * OIDC one — so they are held to one fake rather than to copies that drift.
 * (GitHub is not an OpenID Provider; its tests run on its own fake GitHub.)
 * Endpoints may be named explicitly — Google's and Apple's are not paths
 * under the issuer, and those providers build their metadata locally — or
 * left to default to paths under the issuer, with `discovery` serving the
 * document a discovering provider (federation-oidc) reads at boot.
 */
export interface FakeIdpOptions {
    readonly issuer: string;
    /** Default: `<issuer>/token`. */
    readonly tokenEndpoint?: string;
    /** Default: `<issuer>/jwks`. */
    readonly jwksUri?: string;
    /** Absent for a provider that publishes none (Apple). */
    readonly userinfoEndpoint?: string;
    /** Where `authorize` accepts an authorization request. Default: `<issuer>/authorize`. */
    readonly authorizationEndpoint?: string;
    /** Named in the discovery document only; nothing is served there. */
    readonly endSessionEndpoint?: string;
    /** Serve `metadata` at `<issuer>/.well-known/openid-configuration`. Default: no. */
    readonly discovery?: boolean;
    readonly clientId?: string;
    readonly sub?: string;
}
/** What the user agent carries back to the callback from `authorize`. */
export interface FakeIdpAuthorizationResponse {
    readonly code: string;
    readonly state: string | null;
    /** RFC 9207: the issuer, as an IdP that advertises the parameter sends it. */
    readonly iss: string;
}
export interface FakeIdpRequest {
    readonly url: URL;
    readonly method: string;
    readonly headers: Headers;
    readonly body: URLSearchParams | undefined;
}
export interface FakeIdp {
    readonly issuer: string;
    readonly clientId: string;
    readonly sub: string;
    readonly requests: FakeIdpRequest[];
    readonly fetch: typeof fetch;
    /**
     * The discovery document, served when `discovery` is on. Mutable, so a
     * test can corrupt one field or add one (`authorization_response_iss_
     * parameter_supported`) before the provider under test discovers it.
     */
    readonly metadata: Record<string, unknown>;
    /** The status the discovery document is answered with. */
    discoveryStatus: number;
    /** Claims laid over the id_token defaults. */
    idTokenClaims: Record<string, unknown>;
    /**
     * The nonce a code exchange's id_token echoes for a code `authorize()` did
     * NOT issue; absent when undefined. A code `authorize()` issued carries its
     * own authorization's nonce, whatever this says.
     */
    nonce: string | undefined;
    /** Sign under the current key but claim this `kid` in the header. */
    signingKid: string | undefined;
    /**
     * Sign under a key that was never published, claiming the published `kid`.
     * A valid RS256 signature by the wrong key: the case only a signature
     * check against the JWKS can catch.
     */
    signWithUnpublishedKey: boolean;
    /** Leave the id_token out of the token responses — the code exchange's and the refresh's. */
    omitIdToken: boolean;
    /**
     * Whether a refresh answer carries an id_token. Default `true`: Google and
     * Apple re-issue one, and the library verifies it like the login's.
     */
    refreshWithIdToken: boolean;
    /** Whether the code exchange's id_token carries `at_hash`, and whether it is right. */
    atHash: "none" | "valid" | "wrong";
    /** Claims laid over the userinfo defaults. */
    userinfoClaims: Record<string, unknown>;
    tokenStatus: number;
    /** The body of a token-endpoint refusal (when `tokenStatus` is not 200). */
    refusal: Record<string, unknown>;
    accessToken: string;
    /**
     * Laid over the code exchange's answer; a value of `undefined` removes the
     * field. Lets a test make the answer omit `expires_in`, carry a `scope`,
     * or carry a field of the wrong shape.
     */
    codeAnswer: Record<string, unknown>;
    /** Laid over the refresh answer, as `codeAnswer` is over the code exchange's. */
    refreshAnswer: Record<string, unknown>;
    /** How long the JWKS takes to answer, in real milliseconds. */
    jwksDelayMs: number;
    /**
     * Google's documented rule for a code `authorize` issued: the exchange
     * carries a `refresh_token` only when the authorization asked for
     * `access_type=offline` AND the user was shown the consent screen — the
     * first time this client asks this user, or whenever `prompt` includes
     * `consent`. Default `false`: every exchange carries one.
     */
    refreshTokenOnlyOnConsent: boolean;
    /**
     * Play the user agent and the user at the authorization endpoint: accept
     * the authorization request `url` names (its client, redirect URI, PKCE
     * challenge and nonce are recorded, and that code's id_token echoes that
     * nonce), approve it, and answer what the IdP redirects back with. The
     * token endpoint then holds the exchange of that code to the recorded
     * request: the same redirect URI, a verifier that matches the challenge,
     * one use — a second exchange is `invalid_grant`.
     */
    authorize(url: URL | string): FakeIdpAuthorizationResponse;
    /** Replace the signing key; the JWKS then holds only the new one. */
    rotateKey(): Promise<string>;
    currentKid(): string;
    /**
     * Requests to an endpoint — an absolute URL, or a path under the issuer
     * (`"/token"`) — compared on origin and path (a query string is ignored).
     */
    requestsTo(endpoint: string): FakeIdpRequest[];
    /** The last request to the token endpoint. */
    lastTokenRequest(): FakeIdpRequest | undefined;
}
export declare function createFakeIdp(options: FakeIdpOptions): Promise<FakeIdp>;
//# sourceMappingURL=fake-idp.d.mts.map