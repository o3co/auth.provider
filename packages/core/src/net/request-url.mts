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
 * The canonical-request-URL vocabulary: one definition of "the URL this
 * request reached", built from the deployment's **configured** origin plus the
 * request target the request actually carried. It supplies the expected DPoP
 * `htu` (`@o3co/auth-provider-dpop`) and the `redirect_to` of the `/authorize`
 * login round-trip (`@o3co/auth-provider-oauth`).
 *
 * Security: with Express `trust proxy` on, `req.protocol` follows
 * `X-Forwarded-Proto` and `req.get("host")` follows the client's `Host`, so a
 * URL built from them is attacker-chosen (a proof matching its own `htu`; an
 * open redirect after login). The origin is a property of the deployment
 * (`oauth.jwt.issuer`), never of a request; only the path is the request's.
 *
 * **String concatenation, never `new URL(target, origin)`**: a target of
 * `//evil.example/x` resolves relative to an origin as a protocol-relative URL
 * and would move the host. Concatenated onto an absolute origin, the WHATWG
 * parser reads it as the path it is.
 */

/**
 * Build the URL a request reached from the deployment's configured `origin`
 * (scheme + host + port, e.g. `new URL(issuer).origin`) and the raw request
 * `target` (Express `req.originalUrl`).
 *
 * An absolute-form target (`GET http://x/ HTTP/1.1`, legal per RFC 9112 §3.2)
 * does not start with `/`; it is prefixed with `/` so it stays a path and is
 * never spliced into the authority.
 */
export const buildCanonicalRequestUrl = (origin: string, target: string): string => {
	const path = target.startsWith("/") ? target : `/${target}`;
	return `${origin}${path}`;
};
