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
 * Transport validation for the Store endpoints `HttpUserRepository` posts to.
 *
 * These endpoints receive **plaintext user credentials** — a password on
 * `authenticateUrl`, a bearer-ish token on `authenticateByTokenUrl`. An
 * `http://` URL therefore does not merely weaken the connection, it publishes
 * the credential to every hop on the path. A single mistyped environment
 * variable was enough to do that, and nothing anywhere refused it (#285).
 *
 * ## The loopback carve-out
 *
 * `http://` is accepted for **loopback hosts only** — `localhost`, anything in
 * `127.0.0.0/8`, and `[::1]`. Traffic to a loopback address never leaves the
 * machine, so there is no path to eavesdrop on, and requiring TLS there would
 * force every local development setup and every in-process test fixture to
 * provision a certificate for no security gain. Any other host — including a
 * private-range address such as `10.0.0.5` or a service name on a container
 * network — must use `https://`: those cross a network the deployment does not
 * control end to end, and "internal" is not a synonym for "encrypted".
 *
 * The rule matches `oauth.jwt.issuer`'s (`checkCanonicalIssuer` in
 * `@o3co/auth-provider-core`) so operators meet one policy, not two. It is kept
 * separate rather than reused because the constraints genuinely differ: an
 * issuer may not carry a query string or fragment (OIDC Discovery derives the
 * metadata URL from it), while a Store endpoint is an ordinary POST target for
 * which `?tenant=acme` is legitimate. The loopback *predicate* the carve-out
 * runs on, though, is shared vocabulary: `isLoopbackHostname` comes from
 * `@o3co/auth-provider-core` (`net/loopback`, #364), the same definition the
 * session redirect policy consumes, so the carve-outs cannot drift apart.
 */
import { isLoopbackHostname } from "@o3co/auth-provider-core";
// Re-exported unchanged: this module's callers (and its tests) read the
// predicate as part of the endpoint-validation surface. The definition lives
// in core (#364) — re-exporting is the sanctioned way to surface it.
export { isLoopbackHostname };
/** Matches `scheme://` — the shape that distinguishes an absolute URL from a bare host. */
const ABSOLUTE_URL_PREFIX = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//;
/**
 * Returns `null` when `value` is a usable Store endpoint, otherwise the reason
 * it is not. See the module comment for the loopback carve-out.
 */
export function checkSecureEndpoint(value) {
    if (typeof value !== "string")
        return "not-a-string";
    if (value === "")
        return "empty";
    // `new URL("users.example.com:3000")` succeeds with `users.example.com:` as
    // the scheme and no host, so a bare host is reported as the missing-scheme
    // mistake it is rather than as an exotic scheme.
    if (!ABSOLUTE_URL_PREFIX.test(value))
        return "not-absolute-url";
    let url;
    try {
        url = new URL(value);
    }
    catch {
        return "not-absolute-url";
    }
    if (url.protocol !== "https:" && url.protocol !== "http:")
        return "unsupported-scheme";
    // No empty-host check is needed below: `http` and `https` are "special"
    // schemes, for which the WHATWG parser requires a non-empty host — a
    // host-less `https://` or `https://:8080/x` throws above and is reported as
    // `not-absolute-url` rather than reaching here with `hostname === ""`.
    if (url.protocol === "http:" && !isLoopbackHostname(url.hostname))
        return "insecure-scheme";
    if (url.username !== "" || url.password !== "")
        return "has-credentials";
    return null;
}
/**
 * Operator-facing explanation for each rejection reason.
 *
 * This is what an operator reads at boot when their Store URL is refused, so
 * every message states the **actual** rule rather than a simplification of it.
 * In particular both scheme messages name the loopback carve-out: saying only
 * "must use https" would contradict a policy that does accept `http://` on
 * loopback, and send someone hunting for a certificate they do not need.
 */
export function describeEndpointRejection(reason) {
    switch (reason) {
        case "not-a-string":
            return "must be a string";
        case "empty":
            return 'must not be empty (an unset or blank environment variable substitutes as "")';
        case "not-absolute-url":
            return ("must be an absolute URL with a host (e.g. https://users.example.com/authenticate), " +
                "not a bare host or a path");
        case "unsupported-scheme":
            return ("must use https, or http for a loopback host (localhost, 127.0.0.0/8, [::1]) — " +
                "no other scheme is accepted");
        case "insecure-scheme":
            return ("must use https — it carries plaintext user credentials; http is accepted only for " +
                "a loopback host (localhost, 127.0.0.0/8, [::1])");
        case "has-credentials":
            return "must not embed credentials in the URL";
    }
}
/**
 * Returns `value` when it is a usable Store endpoint, otherwise throws naming
 * `field` and the reason.
 *
 * The rejected value is deliberately **not** echoed into the message: it is
 * operator-supplied configuration that may embed a secret, and a boot error
 * lands in logs.
 */
export function assertSecureEndpoint(value, field) {
    const rejection = checkSecureEndpoint(value);
    if (rejection !== null) {
        throw new Error(`HttpUserRepository: "${field}" ${describeEndpointRejection(rejection)} ` +
            `(reason: ${rejection})`);
    }
    return value;
}
