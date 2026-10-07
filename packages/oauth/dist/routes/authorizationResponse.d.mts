/**
 * The one builder of an authorization response that reaches a client's
 * `redirect_uri` — a code (RFC 6749 §4.1.2) or an error (§4.1.2.1), whether
 * `/authorize` or the consent step answers it. Every such response carries
 * `iss` (RFC 9207 §2), the issuer as discovery advertises it, which discovery
 * promises through `authorization_response_iss_parameter_supported`: a
 * response built anywhere else would break that promise.
 */
/**
 * `redirectUri` with `params` appended, then `state` when the request carried
 * one, then `iss` = `responseIssuer`. Nothing in the registered query is
 * removed or replaced: its names are kept, in order, with their values as
 * WHATWG URL parsing decodes them. Serializing the query as a form may change
 * the bytes (`%20` as `+`), a percent-sequence that is not UTF-8 becomes
 * U+FFFD (`%FF` as `%EF%BF%BD`), and a name with no value gains `=`.
 */
export declare function authorizationResponseUrl(redirectUri: string, params: Readonly<Record<string, string>>, state: string | undefined, responseIssuer: string): string;
/** An authorization response's location, with its `iss` already bound. */
export type AuthorizationResponse = (redirectUri: string, params: Readonly<Record<string, string>>, state: string | undefined) => string;
/**
 * {@link authorizationResponseUrl} bound to `responseIssuer` — core's
 * `advertisedIssuer` of the configured issuer, resolved once at router
 * composition — so the sites that answer never handle an issuer.
 */
export declare function authorizationResponseFor(responseIssuer: string): AuthorizationResponse;
//# sourceMappingURL=authorizationResponse.d.mts.map