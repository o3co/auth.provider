import type { Request } from "express";
/**
 * Read one cookie off a request, whether or not `cookie-parser` is mounted.
 *
 * `cookie-parser` is not a dependency of this package, but a composition root
 * is free to mount it; prefer its output when present and fall back to parsing
 * the raw header. Shared by the CSRF double-submit check and the federation
 * transaction cookie so the two cannot disagree about what "the cookie is
 * present" means.
 */
export declare const readCookie: (req: Request, name: string) => string | undefined;
//# sourceMappingURL=cookies.d.mts.map