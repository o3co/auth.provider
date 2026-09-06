/**
 * Sender-constraint enforcement for **protected resources** — the RFC 9449
 * §7.1 / RFC 8705 §3 counterpart to `tokenBindingMw`.
 *
 * `tokenBindingMw` runs at `/oauth/token` and answers "what binding is this
 * client presenting?" so a grant can stamp it into the issued token's `cnf`.
 * It says nothing about later requests. Without the middleware in this file a
 * `cnf`-bearing access token is accepted at `/oauth/userinfo`, the federation
 * token endpoint, `/oauth/logout`, and bearer self-introspection as an
 * ordinary Bearer JWT — so a stolen DPoP- or mTLS-bound token replays
 * unbound, which is the whole point of binding it (issue #264).
 *
 * What it enforces, for a token that carries a `cnf`:
 *
 *   1. The wire scheme matches the binding. `cnf.jkt` REQUIRES the `DPoP`
 *      auth scheme (RFC 9449 §7.1 — a DPoP-bound token presented as a
 *      Bearer token must be refused); `cnf["x5t#S256"]` keeps `Bearer`,
 *      because RFC 8705 does not redefine the wire-level token type.
 *   2. A mechanism *of the kind that owns that `cnf` variant* validated the
 *      material on this request, and produced the same confirmation value.
 *
 * Deliberately NOT layered on `tokenBindingMw`: that middleware resolves
 * competing mechanisms by `DispatchPolicy` and answers with 400 +
 * `errorEnvelope`. Here the token already names its binding, so there is
 * nothing to arbitrate — the answer must come from the mechanism the token
 * points at — and a protected resource owes RFC 6750 §3 a 401 with a
 * `WWW-Authenticate` challenge.
 */
import type { RequestHandler } from "express";
import type { Logger } from "../logging/Logger.mjs";
import type { TokenBindingMechanism } from "./tokenBinding.mjs";
import "./express.mjs";
export interface ProtectedResourceBindingOptions {
    /**
     * The same mechanisms `tokenBindingMw` is composed from. MAY be empty:
     * a deployment with no mechanisms still has to refuse `cnf`-bearing
     * tokens minted before the mechanism was removed, so an empty list is a
     * meaningful configuration rather than a reason to skip the middleware.
     */
    readonly mechanisms: readonly TokenBindingMechanism[];
    readonly logger?: Logger;
}
export declare const protectedResourceBindingMw: ({ mechanisms, logger, }: ProtectedResourceBindingOptions) => RequestHandler;
//# sourceMappingURL=protectedResourceBinding.d.mts.map