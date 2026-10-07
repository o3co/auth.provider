import type { LoginEntry } from "../../browser-session/types.mjs";
/**
 * A `LoginEntry` for `url` — the fixture configuration's `/login` by
 * default — over core's login-page rule (`loginPageUrlFor`,
 * `loginPageCarriesReturn`): `redirect_to` joined with `?`, or `&` to a page
 * that has a query, before any fragment, the target encoded whole; a page
 * whose own query carries `redirect_to` is refused. Frozen.
 */
export declare function createTestLoginEntry(url?: string): LoginEntry;
//# sourceMappingURL=loginEntry.d.mts.map