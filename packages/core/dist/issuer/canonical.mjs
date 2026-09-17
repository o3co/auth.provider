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
 * Validation for `oauth.jwt.issuer` — the identity every token this deployment
 * mints is bound to, and the value resource servers pin.
 *
 * The issuer is a property of the deployment, never of a request. It used to
 * fall back to the `Host` header when unset, which made `iss` caller-controlled
 * behind a trusted proxy and made the tokens non-portable. RFC 8414 §2 and OIDC
 * Discovery require a stable absolute URL, and that stability is also what makes
 * the provider swappable: a heavy-class OP publishes a fixed `iss` that resource
 * servers already pin.
 */
/** Hosts for which `http:` is accepted — local development has no TLS. */
const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
/**
 * Returns `null` when `value` is a usable canonical issuer, otherwise the
 * reason it is not.
 *
 * Accepts an absolute `https:` URL, with a path prefix if the deployment needs
 * one, and an `http:` URL only for a loopback host. Rejects query strings and
 * fragments (OIDC Discovery derives the metadata URL from the issuer, so either
 * would produce a different document URL than the one served) and embedded
 * credentials.
 */
export function checkCanonicalIssuer(value) {
    if (typeof value !== "string")
        return "not-a-string";
    if (value === "")
        return "empty";
    let url;
    try {
        url = new URL(value);
    }
    catch {
        return "not-absolute-url";
    }
    // `new URL("auth.example.com:3000")` succeeds with `auth.example.com:` as the
    // scheme and no host — exactly what a bare Host-header value parses as, so it
    // is reported as the missing-scheme mistake it is rather than a scheme error.
    if (url.hostname === "")
        return "not-absolute-url";
    if (url.protocol !== "https:" && url.protocol !== "http:")
        return "unsupported-scheme";
    if (url.protocol === "http:" && !LOOPBACK_HOSTNAMES.has(url.hostname))
        return "insecure-scheme";
    if (url.search !== "")
        return "has-query";
    if (url.hash !== "")
        return "has-fragment";
    if (url.username !== "" || url.password !== "")
        return "has-credentials";
    return null;
}
/** Whether `value` is a usable canonical issuer. */
export function isCanonicalIssuer(value) {
    return checkCanonicalIssuer(value) === null;
}
/** Operator-facing explanation for each rejection reason. */
export function describeIssuerRejection(reason) {
    switch (reason) {
        case "not-a-string":
            return "must be a string";
        case "empty":
            return "must not be empty";
        case "not-absolute-url":
            return "must be an absolute URL (e.g. https://auth.example.com), not a bare host";
        case "unsupported-scheme":
            return "must use the https scheme";
        case "insecure-scheme":
            return "must use https except for a loopback host (localhost, 127.0.0.1, [::1])";
        case "has-query":
            return "must not carry a query string";
        case "has-fragment":
            return "must not carry a fragment";
        case "has-credentials":
            return "must not embed credentials";
    }
}
