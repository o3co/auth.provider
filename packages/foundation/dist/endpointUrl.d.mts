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
export { isLoopbackHostname };
/** Why a candidate endpoint was rejected, phrased for a boot-time error. */
export type EndpointRejection = "not-a-string" | "empty" | "not-absolute-url" | "unsupported-scheme" | "insecure-scheme" | "has-credentials";
/**
 * Returns `null` when `value` is a usable Store endpoint, otherwise the reason
 * it is not. See the module comment for the loopback carve-out.
 */
export declare function checkSecureEndpoint(value: unknown): EndpointRejection | null;
/**
 * Operator-facing explanation for each rejection reason.
 *
 * This is what an operator reads at boot when their Store URL is refused, so
 * every message states the **actual** rule rather than a simplification of it.
 * In particular both scheme messages name the loopback carve-out: saying only
 * "must use https" would contradict a policy that does accept `http://` on
 * loopback, and send someone hunting for a certificate they do not need.
 */
export declare function describeEndpointRejection(reason: EndpointRejection): string;
/**
 * Returns `value` when it is a usable Store endpoint, otherwise throws naming
 * `field` and the reason.
 *
 * The rejected value is deliberately **not** echoed into the message: it is
 * operator-supplied configuration that may embed a secret, and a boot error
 * lands in logs.
 */
export declare function assertSecureEndpoint(value: unknown, field: string): string;
//# sourceMappingURL=endpointUrl.d.mts.map