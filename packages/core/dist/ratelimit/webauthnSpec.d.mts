import type { RateLimitSpec } from "./types.mjs";
/**
 * The key prefix `POST /oauth/webauthn/authentication/options` limits under
 * (`webauthn-authentication-options:ip:<ip>`). Defined here, in core, so the
 * seed below and the route that keys on it share one name;
 * `@o3co/auth-provider-webauthn` exports it as
 * `WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG` rather than restating it.
 * Contains no `:`, since an adapter takes the prefix up to the first colon.
 */
export declare const WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_PREFIX = "webauthn-authentication-options";
/**
 * Seed a rate-limiter adapter's `limits` with the WebAuthn options route's
 * spec, drawn from `config.webauthn.rateLimit.authenticationOptions`.
 *
 * The route is unauthenticated and writes a challenge per request; its budget
 * (reference default 30 per 60 s) lives in the WebAuthn section. The route
 * built its per-process fallback from it, but a shared limiter, which a
 * scaled deployment must wire, resolves the prefix from its own `limits`,
 * and nothing seeded it: the route ran on the adapter's `defaultLimit` of
 * 60 per 60 s, silently.
 *
 * Same shape as `resolveLoginLimitSpec` (#270) and
 * `resolveDeviceVerificationLimitSpec` (#448): one config key is the source
 * of truth, seeded into each adapter unless the operator declared the prefix
 * explicitly. An explicit entry is a statement about this adapter and wins.
 * A key that is not given (no `webauthn` section, the package not loaded)
 * seeds nothing. A key that is given is read as `webauthnConfigSchema`
 * coerces it, since `reference.conf` fills both fields from environment
 * variables that HOCON substitutes as strings, and no module's `configSchema`
 * parses this section, so `createApp` hands it on as written. One that the one predicate then refuses is a
 * `RangeError` naming `webauthn.rateLimit.authenticationOptions`, as the
 * other two seeds refuse theirs: the WebAuthn schema refuses it at the config
 * boundary, and a hand-built config that never passed it is still a
 * configuration someone wrote.
 *
 * @param limits  The adapter's own configured limits.
 * @param config  The full application config (only
 *                `webauthn.rateLimit.authenticationOptions` is read).
 */
export declare const resolveWebAuthnAuthenticationOptionsLimitSpec: (limits: Readonly<Record<string, RateLimitSpec>>, config: unknown) => Record<string, RateLimitSpec>;
//# sourceMappingURL=webauthnSpec.d.mts.map