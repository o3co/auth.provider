/**
 * The deployment's login page as core's `LoginEntry` — the `loginEntry` slot
 * the session module provides: the page a browser that is not signed in is
 * sent to (`session.loginPage.url`), and the `redirect_to` protocol that
 * brings it back. `/authorize` and the federation-grants connect flow read it here.
 *
 * `redirect_to` is added to the page's own query (`&`-joined when the page
 * already has one, since a second `?` would corrupt both parameters), the
 * target encoded whole so nothing of it reads as the page's query or
 * fragment. What comes back is the login route's to hold to its allowlist.
 */
import { type LoginEntry } from "@o3co/auth-provider-core";
/**
 * The login entry for the page `url` — a path or an absolute URL, which may
 * carry a query and a fragment of its own, but not `redirect_to`: `urlFor`
 * adds it, and a page that carried one would send two. The rule is core's
 * (`loginPageCarriesReturn`, `loginPageUrlFor`): `redirect_to` in the page's
 * query, before any fragment, the target encoded whole. Frozen.
 */
export declare function createLoginEntry(url: string): LoginEntry;
/**
 * The login entry for the page `written`, as the session module's section
 * carries it at `session.loginPage.url`.
 *
 * Built whether or not the page is written, for a configuration no schema
 * parsed (`loginEntryFromConfig`; the session module's section requires the
 * key). Without a page, `url` and `urlFor` throw, naming the key;
 * `/authorize` and the federation-grants connect flow read `url` when they
 * are built, and refuse to boot.
 */
export declare function loginEntryOf(written: unknown): LoginEntry;
/** The login entry for the page a configuration carries at `session.loginPage.url`. */
export declare function loginEntryFromConfig(config: unknown): LoginEntry;
//# sourceMappingURL=login-entry.d.mts.map