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
 * The canonical-request-URL vocabulary — one definition of "the URL this
 * request reached", reconstructed from the deployment's **configured** origin
 * plus the request target the request actually carried (#292, #356).
 *
 * Consumers today:
 *
 *   - **DPoP `htu` comparison** (`@o3co/auth-provider-dpop`, #292): the
 *     expected `htu` every proof is checked against. Reconstructing it from
 *     `req.protocol` + the `Host` header let a caller behind a trusted proxy
 *     choose the value its own proof had to match.
 *   - **The `/authorize` login round-trip** (`@o3co/auth-provider-oauth`,
 *     #356): the `redirect_to` handed to the login page. Reconstructed from
 *     the same headers it was an open redirect — the caller chose where the
 *     login page sends the browser afterwards.
 *
 * Both attacks arrive through the same door: `req.protocol` follows
 * `X-Forwarded-Proto` and `req.get("host")` follows the client's `Host`
 * whenever Express `trust proxy` is on, so anything security-relevant built
 * from them is attacker-influenced. The origin half of the URL is a property
 * of the deployment (`oauth.jwt.issuer`, required since #307), never of a
 * request; only the path half is the request's to report.
 *
 * **String concatenation, never `new URL(target, origin)`**: a request target
 * of `//evil.example/x` resolves *relative to* an origin as a
 * protocol-relative URL and would move the host — the same spoof arriving
 * through a different door. Concatenated onto an absolute origin the WHATWG
 * parser reads it as the path it is.
 */
/**
 * Build the URL a request reached from the deployment's configured `origin`
 * (scheme + host + port, e.g. `new URL(issuer).origin`) and the raw request
 * `target` (Express `req.originalUrl`).
 *
 * Express reports an origin-form target, which always starts with `/`. An
 * absolute-form target (`GET http://x/ HTTP/1.1`, legal per RFC 9112 §3.2)
 * would not, and must not be spliced into the authority position — it is
 * prefixed with `/` so it stays a path.
 */
export const buildCanonicalRequestUrl = (origin, target) => {
    const path = target.startsWith("/") ? target : `/${target}`;
    return `${origin}${path}`;
};
