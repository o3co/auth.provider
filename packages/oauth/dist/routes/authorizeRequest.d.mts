/**
 * The request's shape: request objects, `response_mode`, single-valued
 * parameters, `claims`, `response_type`, PKCE, `nonce` and `scope`. Every refusal is on the
 * validated `redirect_uri`, and none costs a store or policy call.
 */
import { type PublicClient } from "@o3co/auth-provider-core";
import { type AuthorizeContext } from "./authorizeContext.mjs";
/**
 * Refuses request objects (`request`, `request_uri`), which this server does
 * not implement, with OIDC Core's `request_not_supported` /
 * `request_uri_not_supported`. Ignoring them would be unsafe: the RP would
 * believe its signed, tamper-proof parameters were honoured while the
 * unsigned query was processed instead.
 */
export declare const checkRequestObjectUnsupported: (ctx: AuthorizeContext) => boolean;
/**
 * OAuth 2.0 Multiple Response Type Encoding Practices §2.1 `response_mode`:
 * only `query` is served (discovery's `response_modes_supported`), so any
 * other value, or a repeat, is refused with `invalid_request` rather than
 * answered in a mode the client did not ask for. An empty value is omitted
 * (RFC 6749 §3.1).
 */
export declare const checkResponseMode: (ctx: AuthorizeContext) => boolean;
/** Refuses a repeated single-valued parameter before any of it is interpreted. */
export declare const checkSingleValuedParams: (ctx: AuthorizeContext) => boolean;
/**
 * OIDC Core §5.5 `claims`: a request naming `acr` (for id_token or userinfo,
 * essential or not) is refused with `invalid_request` — this server vouches
 * for `acr` only through `acr_values`, and ignoring the request would return
 * a token the RP reads as honouring it. Other uses of `claims` are ignored
 * (discovery omits `claims_parameter_supported`). An empty value is omitted
 * (RFC 6749 §3.1); any other non-object is malformed. Runs before the
 * re-authentication decision, so a refused request is never first sent to
 * log in.
 */
export declare const checkClaimsParameter: (ctx: AuthorizeContext) => boolean;
export declare const checkResponseTypeIsCode: (ctx: AuthorizeContext) => boolean;
/**
 * PKCE (OAuth 2.1 §4.1.1, RFC 9700 §2.1.1) for every client: a
 * `code_challenge` is required — confidential clients included, since a
 * client secret proves who redeems the code, not that the redeemer is the
 * party it was issued to — and the method is `S256` unless this client's
 * registration opts into `plain` (`pkceMethodsForClient`). Runs before the
 * policy hook so a bad method costs no external I/O.
 */
export declare const checkPkce: (ctx: AuthorizeContext, client: PublicClient, codeChallenge: unknown, codeChallengeMethod: unknown) => {
    method: string;
} | null;
export declare const checkNonce: (ctx: AuthorizeContext) => boolean;
/**
 * RFC 6749 §3.3 scope narrowing plus the openid requirement. Returns the
 * requested scopes and the allowlist-filtered set the policy step takes as
 * its ceiling, or `null` when a response has been sent.
 *
 * Scopes the client is not registered for are dropped (§3.3 allows it; the
 * token response's `scope` names what was granted). An omitted scope draws on
 * the declared `defaultScopes`, never the whole allowlist; with none declared
 * it is `invalid_scope`, except that a client with an empty allowlist keeps
 * the empty grant.
 *
 * Under `oidcMode = "oidc-required"`, the default, the request itself must
 * name `openid`, so an omitted scope is `invalid_scope` there even when the
 * client's `defaultScopes` contain `openid`. The defaults decide an omitted
 * scope only under `dual`.
 */
export declare const resolveScopes: (ctx: AuthorizeContext, scope: unknown, client: PublicClient) => Promise<{
    requestedScopes: string[];
    allowedFilteredScopes: readonly string[];
} | null>;
//# sourceMappingURL=authorizeRequest.d.mts.map