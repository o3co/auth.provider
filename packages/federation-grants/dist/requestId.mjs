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
 * The correlation both routes and the background audit bridge carry
 * (#593, D18).
 *
 * A refresh that is persisted after the HTTP response has been sent is the
 * reason this is the *request's* identifier and not one the late worker mints:
 * an ID generated there cannot be tied back to the call that started the
 * rotation, which is the one question an operator has when a credential
 * changed under them.
 *
 * It is caller-controlled metadata and nothing more. Never authentication,
 * never an idempotency key, never a lock key, never a trusted identifier of a
 * person — so the accepted shape is narrow, and a value outside it is
 * *replaced* rather than repaired. Trimming "job 42" down to "job" would echo
 * a prefix the caller never asked to be correlated by into an operator's logs,
 * and would let a caller choose the bytes that land there.
 */
import { randomUUID } from "node:crypto";
/** The header, in the spelling everything downstream reads it by. */
export const REQUEST_ID_HEADER = "x-request-id";
/**
 * What a supplied value may look like: the printable subset that appears in
 * trace identifiers, up to 128 characters. No spaces, commas or control
 * characters — which is also what makes a header sent twice unusable, since
 * every stack that joins two occurrences does it with a separator outside this
 * set.
 */
const ACCEPTED = /^[A-Za-z0-9._:+/=#-]{1,128}$/;
/**
 * The ID for this request: the caller's when it is usable, a fresh one
 * otherwise.
 *
 * `raw` is `req.headers[REQUEST_ID_HEADER]`, which Node types as
 * `string | string[] | undefined`. The array is the case worth naming: it is
 * what a stack that keeps duplicate occurrences apart produces, and no element
 * of it is a value *one* caller chose, so it is refused as a whole rather than
 * resolved by taking the first.
 */
export function resolveRequestId(raw) {
    if (typeof raw === "string" && ACCEPTED.test(raw))
        return raw;
    return randomUUID();
}
/**
 * Sets the ID on the response before anything else can answer, so that every
 * exit this package owns carries it — the disabled 404, a parser's 400, an
 * authentication challenge, a throttled 429 and the handlers alike.
 */
export function createRequestIdMiddleware() {
    return (req, res, next) => {
        res.set(REQUEST_ID_HEADER, resolveRequestId(req.headers[REQUEST_ID_HEADER]));
        next();
    };
}
/**
 * The ID this response is being answered under.
 *
 * Read back off the response rather than kept in a second place: the header is
 * already the one copy, it is set before anything can answer, and a handler
 * reading it cannot disagree with what the caller is told.
 */
export function requestIdOf(res) {
    const set = res.getHeader(REQUEST_ID_HEADER);
    return typeof set === "string" ? set : "";
}
