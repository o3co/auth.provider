/** OpenID Connect Discovery 1.0 §4: the suffix appended to the issuer. */
export declare const OIDC_DISCOVERY_PATH = "/.well-known/openid-configuration";
/** RFC 8414 §3: the well-known string inserted between host and path. */
export declare const OAUTH_METADATA_PATH = "/.well-known/oauth-authorization-server";
export interface DiscoveryPaths {
    /** Where OIDC Discovery clients look. */
    readonly oidc: readonly string[];
    /** Where RFC 8414 clients look. */
    readonly oauth: readonly string[];
}
/**
 * The paths one authorization-server metadata document is served at, for an
 * issuer identifier (#528) — the one home the discovery route, its route
 * advertisement and the CORS allowlist all read, so the three cannot drift.
 *
 * The two specs form the URL differently once the issuer has a path
 * component (`https://as.example/tenant-a`):
 *
 * - OIDC Discovery 1.0 §4 **appends**: `/tenant-a/.well-known/openid-configuration`.
 * - RFC 8414 §3 **inserts** the well-known string between host and path:
 *   `/.well-known/oauth-authorization-server/tenant-a`.
 *
 * Some clients probe the RFC 8414 form first and fall back to OIDC; some
 * never fall back. Both are served, with the same document.
 *
 * `/.well-known/openid-configuration` at the root is kept for a path-bearing
 * issuer as well, and the asymmetry with RFC 8414 follows from how such an
 * issuer is deployed (v0.13.0 audit). The document's endpoints are the issuer
 * plus each route (`https://as.example/tenant-a/oauth/authorize`) while the
 * routes are mounted at the router's root, so a path-bearing issuer works only
 * behind a proxy that strips the issuer path, or with the router mounted at
 * that path. In both, the OIDC URL a client builds —
 * `/tenant-a/.well-known/openid-configuration` — reaches this router as the
 * root path; dropping the root would break discovery for exactly the
 * deployments that work, and it is what this server served before #528.
 *
 * The RFC 8414 URL a client builds, `/.well-known/oauth-authorization-server/tenant-a`,
 * carries no issuer prefix. A stripping proxy passes it through unchanged, and
 * the inserted path is what is served for it; a router mounted at `/tenant-a`
 * never receives it at all, so that deployment serves RFC 8414 only if it also
 * routes the path to the router at the root. The RFC 8414 *root* form is never
 * the URL a client of this issuer builds, and answering there would be
 * answering for `https://as.example` — which an RFC 8414 §3.3 client must
 * reject — so it is not served.
 *
 * Where the host's root reaches this router with no stripping, the root OIDC
 * path answers with a document for another issuer; for a path-bearing issuer
 * that is also a deployment whose advertised endpoints do not resolve.
 *
 * An issuer that is not a URL, or has no path, gets the two root forms.
 */
export declare function discoveryPathsFor(issuer: string | undefined): DiscoveryPaths;
//# sourceMappingURL=wellKnownPaths.d.mts.map