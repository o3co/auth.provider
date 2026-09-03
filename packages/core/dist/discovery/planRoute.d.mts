/**
 * discovery/planRoute.mts — the OIDC discovery subsystem's boot-planner hook.
 *
 * Keeps ALL OIDC-specific knowledge (the issuer config path, the keyStore
 * signing algorithm, provider activation, document construction + validation,
 * and the spec-fixed discovery path) out of the generic boot planner
 * (`boot/assemble-app.mts`). The planner calls {@link planDiscoveryRoute} and
 * gets back either a normal route contribution or `null`; from `assembleApp`'s
 * perspective discovery is just another route that flows through the standard
 * collision-check + mount-order + mount pipeline — no special-casing.
 */
import type { Router } from "express";
import type { RouteContribution } from "../modules/manifest/route-contribution.mjs";
/**
 * Plan the core-synthesized OIDC discovery route from the aggregated
 * `discoveryMetadata` contributions, or return `null` when discovery should not
 * be served.
 *
 * Returns a route contribution (mounted at "/", advertising
 * `GET /.well-known/openid-configuration`) when BOTH:
 *   1. an issuer is configured (`config.oauth.jwt.issuer`), and
 *   2. some contribution declares `providerRoot: true` — the EXPLICIT
 *      "an OpenID Provider exists here" signal. An ancillary contributor like
 *      the JWKS module (only `jwks_uri`) leaves it unset, so a key-publishing
 *      deployment can mount JWKS without being treated as a provider; and a
 *      provider that does not expose `authorization_endpoint` (CIBA, device
 *      flow) still activates discovery instead of silently serving nothing.
 *
 * The assembled document is validated by {@link buildDiscoveryDocument}; a
 * `DiscoveryDocumentError` (missing required field, reserved-field
 * contribution, conflicting values, …) is wrapped in a `BootError`
 * (`reason: "discovery-document-invalid"`) so discovery misconfiguration
 * surfaces through the same boot-failure taxonomy as every other assembleApp
 * error.
 */
export declare function planDiscoveryRoute(input: {
    readonly components: Record<string, unknown>;
    readonly registries: ReadonlyMap<string, unknown>;
    readonly routerFactory: () => Router;
}): RouteContribution | null;
//# sourceMappingURL=planRoute.d.mts.map