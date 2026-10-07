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
 * The browser flow's one reading of each value it takes from a request: a
 * parameter, the express session id, the cookie's claim, whether it is a
 * prefetch or a step-up trip's return, and the callback's parameters for the
 * adapter. Reads only. A single parameter that is not a non-empty string is
 * absent; the callback's parameters keep every string value, empty ones
 * included, except `code` and `state`.
 */
import { cookieClaim } from "@o3co/auth-provider-core";
import { STEPPED_UP_PARAMETER } from "./lodgeRoute.mjs";
export const single = (value) => typeof value === "string" && value.length > 0 ? value : undefined;
/** The express session's own id: one half of the browser binding, the durable `sid` the other. */
export const sessionIdOf = (req) => single(req.sessionID);
/**
 * The cookie's claim, core's one reading of it (`cookieClaim`). `req.session`
 * is the session middleware's field, which this package does not type.
 */
export const claimOf = (req) => cookieClaim(req);
/**
 * Whether this connect is a step-up trip's return: the marker, exactly as
 * connect sets it. Anything else is no marker, which only offers the trip.
 */
export const isSteppedUpReturn = (req) => single(req.query[STEPPED_UP_PARAMETER]) === "1";
/** A browser prefetching a link has not asked for it: nothing is parked on its behalf. */
export const isPrefetch = (req) => {
    const purpose = `${req.get("sec-purpose") ?? ""} ${req.get("purpose") ?? ""}`.toLowerCase();
    return purpose.includes("prefetch") || purpose.includes("prerender");
};
/**
 * The rest of the callback's parameters, string values only, without `code`
 * and `state` — which the flow binds itself — exactly as `exchangeCode` takes
 * them, so an adapter forwards `iss` (RFC 9207) the one way it knows.
 */
export function callbackParamsOf(req) {
    const params = {};
    for (const [key, value] of Object.entries(req.query)) {
        if (key === "code" || key === "state")
            continue;
        if (typeof value === "string")
            params[key] = value;
    }
    return params;
}
