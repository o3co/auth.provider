/**
 * The serialized-origin vocabulary — what a configured browser origin may be
 * (#500).
 *
 * `cors.allowedOrigins` is matched against the `Origin` request header by
 * **exact string equality**, so every rule here exists to stop an entry that
 * would parse cleanly at boot and then never match a real request. A CORS
 * allowlist that silently never matches is worse than one that is absent: the
 * operator has stated an intent, the config looks right, and every request
 * fails at the browser with no server-side trace.
 *
 * A serialized origin is what RFC 6454 §6.1 / the WHATWG URL Standard's
 * "origin" serialization produces, and what a browser puts in the header:
 * scheme, host, and a port only when it is not the scheme's default. Nothing
 * else — no path, no `/`, no query, no fragment, no userinfo.
 *
 * The check is therefore mostly one line: parse it, serialize the origin, and
 * require the two to be **identical**. That single comparison catches the
 * whole family at once, and each member of the family is a real typo:
 *
 *   - `https://example.com/` — a trailing slash. Copy-pasted from a browser
 *     address bar every time.
 *   - `https://example.com:443` — an explicit default port. The browser sends
 *     `https://example.com`.
 *   - `https://EXAMPLE.com` — mixed case. The browser lowercases the host.
 *   - `https://example.com/app`, `?x=1`, `#f` — a URL where an origin was
 *     wanted.
 *   - `https://u:p@example.com` — userinfo, which an origin never carries.
 *
 * Two rules do not fall out of that comparison and are stated explicitly:
 *
 *   - **No wildcards.** `https://*.example.com` round-trips through
 *     `URL.origin` unchanged — WHATWG accepts `*` in a host — so the
 *     comparison alone would admit it, and it would then match nothing. There
 *     is no subdomain matching here and there is not going to be: a wildcard
 *     allowlist entry is how a forgotten subdomain takeover becomes a token
 *     endpoint the attacker can read.
 *   - **`https:`, or `http:` for a loopback host.** The same carve-out
 *     `checkSecureEndpoint`, `checkRedirectShape` and `checkRedirectUri`
 *     consume, through the shared {@link isLoopbackHostname} home (#364).
 *     Letting a plaintext origin read token responses is a downgrade of the
 *     whole exchange; letting `http://localhost:5173` do it is how a front-end
 *     dev server works. Opaque-origin schemes (anything WHATWG serializes as
 *     `"null"` — custom app schemes, `data:`) are refused by name: a browser
 *     sends the literal `Origin: null` for those, which is not a value an
 *     allowlist can safely name, because every sandboxed document in the world
 *     shares it.
 */
/**
 * Read `cors.allowedOrigins` from whatever shape it arrived in.
 *
 * Two shapes are legitimate and both have to work at every reader:
 *
 *   - an array, which is what `application.conf` and a hand-built `AppConfig`
 *     carry, and
 *   - a comma-separated string, which is the only shape an environment
 *     variable can carry a list in (`${?CORS_ALLOWED_ORIGINS}`).
 *
 * It lives here, beside {@link checkSerializedOrigin}, because the config
 * schema is not the only reader. `assembleApp` decides whether to mount the
 * CORS middleware from `components.config`, and that config has not
 * necessarily been through `AppConfigSchema`: the boot pipeline validates with
 * the core schema and shallow-merges the raw top-level extras back over the
 * result, so an operator who set the environment variable — the documented way
 * to configure this — would hand the mount site a string. Testing that for
 * `Array.isArray` answered "no origins configured" and mounted nothing, with
 * no error and no log: precisely the silent no-op this key was wired up to
 * stop being.
 *
 * Only the shape is normalised here. Each entry is still checked with
 * {@link checkSerializedOrigin} by both the schema (which fails boot naming
 * the index) and the middleware (which drops it with a warning), so this
 * cannot widen an allowlist — it can only stop one being dropped whole.
 *
 * Anything that is neither an array nor a string yields no origins; the caller
 * decides whether that shape deserves a warning.
 */
export declare function normalizeAllowedOrigins(raw: unknown): readonly string[];
/** Why a configured origin was refused. */
export type SerializedOriginRejection = {
    reason: "unparsable";
} | {
    reason: "wildcard";
} | {
    reason: "opaque-origin";
    scheme: string;
} | {
    reason: "insecure-scheme";
    scheme: string;
    hostname: string;
} | {
    reason: "not-serialized";
    serialized: string;
};
/**
 * Check one configured origin against the rules above. Returns `null` when
 * acceptable, a {@link SerializedOriginRejection} otherwise.
 *
 * Pure and exported (with {@link describeSerializedOriginRejection}) so the
 * config schema and the CORS middleware hold the same vocabulary — the
 * middleware re-applies it so a hand-built `AppConfig` that never passed the
 * schema cannot install an entry the schema would have refused.
 */
export declare function checkSerializedOrigin(raw: string): SerializedOriginRejection | null;
/** Operator-facing wording for one {@link SerializedOriginRejection}. */
export declare function describeSerializedOriginRejection(rejection: SerializedOriginRejection): string;
//# sourceMappingURL=origin.d.mts.map