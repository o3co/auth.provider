/**
 * The login page's URL rule: the one home of the rule `LoginEntry` states, so
 * `/authorize`'s own fallback (oauth, when no module provides the slot) and
 * the session package's `loginEntry` cannot drift apart.
 *
 * The page's own query is the text after the first `?` and before any `#`,
 * so a fragment is never mistaken for the query and a URL that `URL` cannot
 * parse is still read. `redirect_to` joins that query (`&` or `?`) before the
 * kept fragment; the target is encoded whole with `encodeURIComponent`, never
 * as a form, so nothing of it reads as the page's query or fragment.
 */
/** The parameter a login page reads where to come back to from. */
export declare const LOGIN_RETURN_PARAMETER = "redirect_to";
/**
 * Whether `page`'s own query already carries `redirect_to` — the name matched
 * as `URLSearchParams.has` matches it, so `redirect%5Fto` and one with no
 * value count. Such a page is refused: a sender adds `redirect_to`, and the
 * page would receive two.
 */
export declare function loginPageCarriesReturn(page: string): boolean;
/** `page` with `redirect_to` naming `returnTo` added to its query, before any fragment. */
export declare function loginPageUrlFor(page: string, returnTo: string): string;
//# sourceMappingURL=login-page.d.mts.map