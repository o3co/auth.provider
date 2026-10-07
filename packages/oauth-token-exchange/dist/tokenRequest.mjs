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
import { invalidRequest } from "./answers.mjs";
export function readTokenRequest(ctx) {
    const body = ctx.body;
    const subjectToken = typeof body.subject_token === "string" ? body.subject_token : null;
    const subjectTokenType = typeof body.subject_token_type === "string" ? body.subject_token_type : null;
    // Through `/oauth/token`, Basic-authenticated callers omit `client_id` from the
    // body, so the effective client id is the body's, else the authenticated
    // client's. A present value that is not one string (a repeated parameter) is
    // malformed, not ignored: ignoring it would bypass client authentication's
    // equality check.
    const bodyClientIdRaw = body.client_id;
    let bodyClientId;
    if (bodyClientIdRaw === undefined || bodyClientIdRaw === null) {
        bodyClientId = null;
    }
    else if (typeof bodyClientIdRaw === "string") {
        bodyClientId = bodyClientIdRaw;
    }
    else {
        return invalidRequest("client_id must be a single string value");
    }
    const clientId = bodyClientId ?? ctx.authenticatedClient?.clientId ?? null;
    const clientSecretRaw = body.client_secret;
    let clientSecret;
    if (clientSecretRaw === undefined || clientSecretRaw === null) {
        // Confidential clients only: `ClientRepository` cannot tell "no secret
        // configured" from "secret omitted", so accepting an unauthenticated `client_id`
        // would let a stolen subject_token be exchanged under any client's allowlist.
        clientSecret = null;
    }
    else if (typeof clientSecretRaw === "string") {
        clientSecret = clientSecretRaw;
    }
    else {
        // Present but not a string (a repeated parameter): treating it as omitted would
        // bypass the confidential-client check.
        return invalidRequest("client_secret must be a single string value");
    }
    // The lifetime the client asks for, in seconds. RFC 8693 defines no such
    // parameter and RFC 6749 §3.2 has a server ignore unknown ones, so omitting it
    // (or sending it empty) gets the configured default. A malformed value is refused
    // rather than reinterpreted. Honoured at issuance as
    // `min(requested ?? default, max, subject remaining)`.
    const requestedExpiresIn = parseRequestedExpiresIn(body.expires_in);
    if (requestedExpiresIn === MALFORMED) {
        return invalidRequest("expires_in must be sent once, as a positive whole number of seconds in ASCII digits");
    }
    const actorToken = typeof body.actor_token === "string" ? body.actor_token : null;
    const actorTokenType = typeof body.actor_token_type === "string" ? body.actor_token_type : null;
    const requestedTokenType = typeof body.requested_token_type === "string" ? body.requested_token_type : null;
    if (!subjectToken || !subjectTokenType || !clientId) {
        return invalidRequest("subject_token, subject_token_type, client_id are required");
    }
    return {
        body,
        subjectToken,
        subjectTokenType,
        bodyClientId,
        clientId,
        clientSecret,
        requestedExpiresIn,
        actorToken,
        actorTokenType,
        requestedTokenType,
    };
}
/** What {@link parseRequestedExpiresIn} answers for a present, unusable value. */
const MALFORMED = Symbol("malformed");
/**
 * The longest `expires_in` digit string read as a lifetime: ten digits is over
 * three centuries, far past any `maxExpiresIn`, so large values are clamped
 * rather than refused, and within `Number`'s exact range.
 */
const MAX_REQUESTED_EXPIRES_IN_DIGITS = 10;
const REQUESTED_EXPIRES_IN_SHAPE = new RegExp(`^[0-9]{1,${MAX_REQUESTED_EXPIRES_IN_DIGITS}}$`);
/**
 * Reads `expires_in`: `undefined` when absent or empty (RFC 6749 §3.2), the
 * seconds when it is one string of ASCII digits denoting a positive integer, else
 * `MALFORMED`. Narrower than `Number(value)`, which accepts whitespace, signs,
 * decimals, exponents and hex and reads `""` as `0`. A repeated parameter (an
 * array) is refused: the grant cannot tell which value was meant.
 */
function parseRequestedExpiresIn(value) {
    if (value === undefined || value === null || value === "")
        return undefined;
    if (typeof value !== "string" || !REQUESTED_EXPIRES_IN_SHAPE.test(value))
        return MALFORMED;
    const seconds = Number(value);
    return seconds > 0 ? seconds : MALFORMED;
}
