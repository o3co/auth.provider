import { isLoopbackHostname } from "@o3co/auth-provider-core";
import type { FederationResult } from "./federations/types.mjs";
/**
 * The one place a consumer-supplied `redirect_to` is checked against the
 * deployment's policy.
 *
 * ## Why an allowlist, and why it fails closed
 *
 * The pre-#278 rule was "any absolute http(s) URL, narrowed to `sessionDomain`
 * **if one is configured**". `sessionDomain` is optional and defaults to
 * absent, so the shipped default admitted every http(s) URL on the internet.
 * `/session/oauth/federation/:name?redirect_to=…` therefore let anyone hand a
 * victim a link that authenticated at the real IdP and then landed the browser
 * on an attacker's page — the textbook open redirect, and here with a freshly
 * minted session behind it.
 *
 * So the allowlist is the authority, and an **absent allowlist is the empty
 * allowlist**: no `redirect_to` value is accepted at all. Nothing falls back to
 * "any http(s) URL", because a fallback is exactly how the permissive branch
 * survived being written down as a rule. A deployment that never accepts
 * `redirect_to` needs no configuration and keeps working; one that does must
 * say which targets it means.
 *
 * ## Why this lives at the package root rather than under `federations/`
 *
 * #278 fixed the federation entry point. `POST /session/login` kept the
 * pre-#278 rule verbatim and went on storing any absolute http(s) URL under
 * `req.session.redirectTo` (#405) — the same vulnerability, one route over,
 * left behind because the rule had been written down in a place the login
 * route had no reason to import from. Both routes now build their policy from
 * this module, so the rule cannot hold on one entry point and not the other.
 * `federations/redirect-policy.mjs` re-exports the public names unchanged; it
 * adds `resolveCallbackRedirect`, which is federation-specific.
 *
 * ## Exact match
 *
 * A candidate matches when its **normalized** form equals an entry's. The
 * normalization is `new URL(x).href`, so scheme and host case, the default
 * port, `..` segments and percent-encoding are insignificant, and everything
 * else — path, query, fragment, port — is significant. There is no prefix,
 * suffix, wildcard or subdomain matching: `https://app.example.com/dashboard`
 * does not admit `…/dashboard?next=//evil.com`, and an entry does not admit
 * its own siblings. That is deliberately strict, because every relaxation of
 * redirect matching that has ever shipped anywhere has turned out to be an
 * open redirect in a costume.
 *
 * The consequence for operators is that a target carrying dynamic query
 * parameters cannot be allowlisted as a family; it has to become a fixed path
 * with the variable part carried in the session instead.
 *
 * ## The loopback carve-out
 *
 * `http://` is accepted for **loopback hosts only** — `localhost`, anything in
 * `127.0.0.0/8`, and `[::1]` — matching `checkSecureEndpoint`
 * (`@o3co/auth-provider-foundation`, #285) and `checkCanonicalIssuer`
 * (`@o3co/auth-provider-core`). Native clients redirect to a loopback listener
 * (RFC 8252 §7.3) and local development serves the consumer app over plain
 * HTTP; neither can obtain a certificate, and traffic to a loopback address
 * never leaves the machine, so there is nothing on that path to eavesdrop on.
 * Any other host must use `https://` — including a private-range address or a
 * container-network service name, which do cross a network the deployment does
 * not control end to end.
 *
 * The carve-out is about the **scheme**, not the matching: a loopback entry is
 * still matched exactly, port included. RFC 8252 §7.3's port-agnostic loopback
 * comparison is deliberately **not** implemented — `redirect_to` here is the
 * consumer app's landing page, whose port a development or native setup knows
 * in advance, so a port wildcard would widen the surface to buy nothing.
 *
 * ## The cookie domain
 *
 * The session cookie domain (`session.domain`, surfaced to a federation config
 * as `sessionDomain`) was, before #278, the only constraint on a redirect
 * target. It survives as a **narrowing** check on the allowlist itself,
 * applied when the policy is constructed: an entry outside the configured
 * domain is refused at boot rather than sitting in the config looking
 * effective. Dropping it instead would have silently widened what existing
 * deployments accept, which a security fix must not do. Loopback entries are
 * exempt, because a native client's `http://127.0.0.1:PORT` can never be
 * inside a cookie domain and is precisely the case the carve-out exists for —
 * applying the domain check to it would make the carve-out unreachable for
 * every deployment that sets a cookie domain.
 *
 * An operator who genuinely needs a cross-domain redirect target unsets the
 * cookie domain, which is then an explicit decision rather than a silent one.
 *
 * ## Where the loopback rule lives
 *
 * `isLoopbackHostname` is imported from `@o3co/auth-provider-core`
 * (`net/loopback`, #364) — the same definition `checkSecureEndpoint`
 * (`@o3co/auth-provider-foundation`, #285) runs on — and re-exported here
 * unchanged, because this package's public API surfaces it. An earlier
 * revision kept a local copy instead (on the correct observation that
 * `session` must not grow a dependency edge to `foundation`), and the copies
 * drifted within one commit; `core`, which both packages already depend on,
 * is the vocabulary home #292 established. The rejection vocabulary below
 * still follows `checkSecureEndpoint`'s (`<reason>` token plus an
 * operator-facing sentence that states the actual rule) rather than
 * inventing a dialect.
 */
export { isLoopbackHostname };
/** The longest `redirect_to` accepted, checked before the value is parsed. */
export declare const MAX_REDIRECT_URL_LENGTH = 2048;
/**
 * Why a redirect target was refused.
 *
 * The first seven are shape faults and apply both to a request-time candidate
 * and to an allowlist entry. `outside-session-domain` only ever applies to an
 * entry (it is checked when the policy is built); `no-allowlist` and
 * `not-allowlisted` only ever apply to a candidate.
 */
export type RedirectRejection = "not-a-string" | "empty" | "too-long" | "not-absolute-url" | "unsupported-scheme" | "insecure-scheme" | "has-credentials" | "outside-session-domain" | "no-allowlist" | "not-allowlisted";
/**
 * Operator-facing explanation for each rejection reason.
 *
 * Every message states the **actual** rule rather than a simplification of it —
 * in particular both scheme messages name the loopback carve-out, because
 * "must use https" would contradict a policy that does accept `http://` on
 * loopback and send someone hunting for a certificate they do not need.
 *
 * `allowlistConfigKey` is the config path the reader has to edit. It is a
 * parameter because the same rule now guards two entry points configured in
 * two places (#405): pointing a login-flow operator at a federation key would
 * send them to edit a section that has no effect on the request they are
 * debugging.
 */
export declare function describeRedirectRejection(reason: RedirectRejection, options?: {
    readonly allowlistConfigKey?: string;
}): string;
/**
 * Returns `null` when `value` is well-formed enough to be a redirect target,
 * otherwise the reason it is not. Shared by allowlist entries and request-time
 * candidates so the two can never drift apart.
 */
export declare function checkRedirectShape(value: unknown): RedirectRejection | null;
/**
 * What a redirect allowlist is built from.
 *
 *   - `redirectAllowlist`: the exact URLs a `redirect_to` may name. Absent or
 *     empty means *nothing* is accepted — see the module comment.
 *   - `sessionDomain`: the session cookie domain; every non-loopback allowlist
 *     entry must be inside it, checked when the policy is built. `null` and
 *     `""` mean the same thing as absent — `session.domain` is nullable in the
 *     application config and optional in a federation config, and a policy that
 *     read those two spellings differently would apply the narrowing check to
 *     one caller and not the other.
 *   - `allowlistConfigKey`: the config path named back to an operator on a
 *     refusal (e.g. `session.redirectAllowlist`).
 *   - `factoryName`: prefix for the boot-time entry-rejection message, so the
 *     line names the builder that refused to start.
 */
export interface RedirectAllowlistOptions {
    readonly redirectAllowlist?: readonly string[] | undefined;
    readonly sessionDomain?: string | null | undefined;
    readonly allowlistConfigKey?: string | undefined;
    readonly factoryName: string;
}
/** Validation for a consumer-supplied `redirect_to`. */
export interface RedirectAllowlistValidator {
    /**
     * Returns `{ ok: true }` when the URL passes the allowlist; otherwise a
     * failure carrying HTTP status, OAuth error code and description suitable
     * for direct response.
     */
    validateRedirect(url: string): FederationResult<void>;
}
/**
 * Builds the exact-match, fail-closed redirect validator both entry points run.
 *
 * Throws when `redirectAllowlist` holds an entry that could never match — see
 * `normalizeAllowlist`. An **absent** allowlist does not throw: a deployment
 * that never accepts `redirect_to` is correctly configured, and its refusal
 * surfaces on the request that actually asks for a redirect.
 */
export declare function createRedirectAllowlistValidator(options: RedirectAllowlistOptions): RedirectAllowlistValidator;
//# sourceMappingURL=redirect-allowlist.d.mts.map