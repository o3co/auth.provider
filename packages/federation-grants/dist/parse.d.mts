/**
 * The domain body of `POST /oauth/federation-grants/:grantId/token` (#593, D10).
 *
 * Every field is an *assertion*: something the caller claims about the grant
 * it is asking against, which core then checks against what was consented to.
 * None of them widens anything — asking for a scope the grant does not carry
 * is a refusal, never a request — so this hands core exactly what was written,
 * or refuses before core is asked at all.
 *
 * It deliberately does not judge `min_ttl`. Whether the number is negative, or
 * larger than the connection permits, is core's decision and comes back as
 * `invalid_request/min_ttl_out_of_range`: one answer to one question, rather
 * than two layers each carrying their own idea of a bound only one of them
 * can see.
 */
/** What the parse produces, in the shape `RetrieveFederationGrantTokenRequest` wants it. */
export interface FederationGrantTokenRequestBody {
    readonly subject: string;
    readonly connection?: string;
    readonly scope?: readonly string[];
    readonly resource?: string;
    readonly minTtlSeconds?: number;
}
export type ParsedFederationGrantTokenRequest = {
    readonly ok: true;
    readonly value: FederationGrantTokenRequestBody;
}
/**
 * A stable identifier, and never prose (D9).
 *
 * It used to be a sentence — `"sub is required"` — which reads well and is
 * useless: a caller that wants to branch on it has to match on English,
 * and the day the wording improves every one of those callers breaks. The
 * identifiers are `snake_case`, are part of the contract, and are what the
 * exit tables in the README and the ADR list.
 *
 * The promise covers what **this package** answers. What it inherits —
 * client authentication's 401s, the shared limiter's 503 — still carries
 * that middleware's own wording, and rewriting it per route would make the
 * same failure read differently on `/token` and on `/revoke`.
 */
 | {
    readonly ok: false;
    readonly description: string;
};
export declare function parseFederationGrantTokenRequest(body: unknown): ParsedFederationGrantTokenRequest;
/**
 * The status route's body: `{"sub": "..."}` and nothing else.
 *
 * The token route's assertions are **refused** here rather than ignored. A
 * caller that sent `min_ttl` to `/status` asked a question this route does not
 * answer, and a 200 describing the grant would read as though it had — status
 * says what the grant IS, not what a token would be.
 */
export declare function parseFederationGrantStatusRequest(body: unknown): ParsedFederationGrantTokenRequest;
/**
 * The revoke route's body: `{"sub": "..."}`, and the same refusal for anything
 * else.
 *
 * `scope`, `resource`, `connection` and `min_ttl` are conditions on a *token*.
 * A withdrawal has no conditions — the grant either belongs to this caller and
 * this subject or it does not — and accepting a field that reads like a
 * condition would suggest one was honoured.
 */
export declare function parseFederationGrantRevokeRequest(body: unknown): ParsedFederationGrantTokenRequest;
/** What a lodging body says, in the shape core's lodging takes. */
export interface FederationGrantLodgingBody {
    readonly subject: string;
    /** Required on a first intent; on a renewal an assertion about the grant, and nothing more. */
    readonly connection?: string;
    readonly redirectUri: string;
    readonly clientState: string;
    readonly scope?: readonly string[];
    readonly expiresInSeconds?: number;
    readonly upstreamSubject?: string;
}
export type ParsedFederationGrantLodgingRequest = {
    readonly ok: true;
    readonly value: FederationGrantLodgingBody;
} | {
    readonly ok: false;
    readonly description: string;
};
/** `POST /oauth/federation-grants`: `connection` is required. */
export declare function parseFederationGrantCreateRequest(body: unknown): ParsedFederationGrantLodgingRequest;
/**
 * `POST /oauth/federation-grants/:grantId/reauthorize`: the connection is the
 * grant's. One sent anyway is an assertion, checked against the grant, and never
 * a way to move it to another connection.
 */
export declare function parseFederationGrantReauthorizeRequest(body: unknown): ParsedFederationGrantLodgingRequest;
//# sourceMappingURL=parse.d.mts.map