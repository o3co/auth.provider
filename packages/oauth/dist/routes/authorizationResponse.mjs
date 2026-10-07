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
export function authorizationResponseUrl(redirectUri, params, state, responseIssuer) {
    const url = new URL(redirectUri);
    for (const [name, value] of Object.entries(params))
        url.searchParams.append(name, value);
    if (state !== undefined)
        url.searchParams.append("state", state);
    url.searchParams.append("iss", responseIssuer);
    return url.toString();
}
/**
 * {@link authorizationResponseUrl} bound to `responseIssuer` — core's
 * `advertisedIssuer` of the configured issuer, resolved once at router
 * composition — so the sites that answer never handle an issuer.
 */
export function authorizationResponseFor(responseIssuer) {
    return (redirectUri, params, state) => authorizationResponseUrl(redirectUri, params, state, responseIssuer);
}
