/**
 * The registered-redirect-URI shape vocabulary (#395, from #293 item 1).
 *
 * A registration carrying `javascript:alert(1)`, a fragment, or userinfo used
 * to boot cleanly and become a valid redirect target — while the logout
 * metadata fields in the same schema were already URL-validated. The wall this
 * checker stands on is elsewhere (registration is operator-only, matching is
 * exact string equality, PKCE is mandatory); what it stops is the misconfig
 * foot-gun, at boot, where the operator is looking.
 *
 * The rules, and why each is shaped the way it is:
 *
 * - **Parse-then-check, never raw string comparison** — the one clause the
 *   #395 falsification pass promoted to a requirement. WHATWG `new URL()`
 *   strips ASCII tab/newline and lowercases the scheme, so `java\tscript:`
 *   REACHES the deny check as `javascript:`; a raw prefix match would have
 *   missed it. Anything the parser refuses, this refuses.
 * - **No fragment** (RFC 6749 §3.1.2 MUST NOT) and **no userinfo** — both are
 *   redirect-response corruption vectors with no legitimate registration use.
 * - **`https:` allowed; `http:` for loopback hosts only** — the same carve-out
 *   `checkSecureEndpoint` and `checkRedirectShape` consume, via the shared
 *   {@link isLoopbackHostname} home (#364).
 * - **Custom schemes by grammar, not enumeration**: allowed only when the
 *   scheme contains a `.` — RFC 8252 §7.1's reverse-domain shape
 *   (`com.example.app:/callback`). Every executable/pseudo scheme
 *   (`javascript:`, `data:`, `blob:`, `file:`, `intent:`, …) is dotless and
 *   falls out structurally, with nothing to keep enumerated. A deny check on
 *   the scheme's FIRST dot-separated label backs it up, so a future
 *   `javascript.something:` spelling cannot ride the grammar in.
 * - **No legacy escape hatch, deliberately**: a dotless custom scheme
 *   (`myapp:`) is refused with no config bypass. That is a documented
 *   capability decision (#395), not an oversight — RFC 8252 §7.1 says SHOULD
 *   reverse-domain, and a quiet flag would be two spellings for one decision.
 */
/** Why a registered redirect URI was refused. */
export type RedirectUriRejection = {
    reason: "unparsable";
} | {
    reason: "control-characters";
} | {
    reason: "fragment";
} | {
    reason: "userinfo";
} | {
    reason: "http-non-loopback";
    hostname: string;
} | {
    reason: "executable-scheme";
    scheme: string;
} | {
    reason: "scheme-not-reverse-domain";
    scheme: string;
};
/**
 * Check one registered redirect URI against the shape rules above. Returns
 * `null` when acceptable, a {@link RedirectUriRejection} otherwise. Pure and
 * exported (with {@link describeRedirectUriRejection}) so a custom
 * `ClientRepository` — which bypasses `ClientEntrySchema` by design — can hold
 * its own registrations to the same vocabulary.
 */
export declare function checkRedirectUri(raw: string): RedirectUriRejection | null;
/** Operator-facing wording for one {@link RedirectUriRejection}. */
export declare function describeRedirectUriRejection(rejection: RedirectUriRejection): string;
//# sourceMappingURL=redirect-uri.d.mts.map