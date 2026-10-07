/**
 * The authorization response an adapter hands to its OAuth library for the
 * code exchange (openid-client's `authorizationCodeGrant` reads it from a URL).
 *
 * The route does not pass the raw callback URL to an adapter: it has already
 * bound `code` and `state`, and delivers the rest as an unsigned bag
 * (`callbackParams`). So each adapter rebuilds the URL, and what goes onto it
 * decides what the library checks.
 *
 * - `code` always.
 * - `iss`, when the callback carried one (RFC 9207). The library compares it
 *   with the issuer the adapter configured, and requires it when that issuer's
 *   metadata advertises `authorization_response_iss_parameter_supported`.
 *   Dropping it skips the mix-up check, and fails every login against an
 *   issuer that advertises the parameter (#595, #597).
 * - Nothing else. The bag is relayed through the user agent, and an `error`,
 *   `response`, `id_token` or `token` on this URL would change how the library
 *   reads the response. `state` never reaches an adapter.
 *
 * One place, so that the adapters cannot drift apart on this rule.
 */
export declare function callbackUrlForExchange(params: {
    readonly redirectUri: string;
    readonly code: string;
    readonly callbackParams?: Readonly<Record<string, string>>;
}): URL;
//# sourceMappingURL=callback-url.d.mts.map