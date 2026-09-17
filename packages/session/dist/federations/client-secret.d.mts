/**
 * A federation's `client_secret`, either fixed or computed per token exchange.
 *
 * Most IdPs issue a long-lived opaque string, and that stays the shape a
 * config file can carry — `federations.google.clientSecret = "..."` is
 * unchanged and keeps working.
 *
 * Some do not. Apple's `client_secret` is an ES256 JWT the relying party signs
 * itself, capped at six months, so it has to be regenerated: expressing it as
 * a value would mean a deployment that silently stops authenticating half a
 * year after it was configured. The function form lets the adapter own that
 * lifecycle — including any caching, which this module deliberately does not
 * do, because only the adapter knows when its secret expires.
 *
 * The union (rather than a second `clientSecretProvider` key) is the whole
 * API: one field, one meaning — "the secret to present at the token
 * endpoint" — with the callable form saying only that it is computed rather
 * than stored.
 */
export type FederationClientSecret = string | (() => string | Promise<string>);
/**
 * Resolve a {@link FederationClientSecret} to the string to present at the
 * token endpoint.
 *
 * Called once per token exchange (and per refresh), never memoised here. An
 * empty or non-string result is rejected rather than forwarded: posting an
 * empty `client_secret` to an IdP produces an opaque `invalid_client` from
 * upstream, which is a much harder thing to diagnose than a local throw
 * naming the federation contract.
 */
export declare const resolveClientSecret: (secret: FederationClientSecret) => Promise<string>;
//# sourceMappingURL=client-secret.d.mts.map