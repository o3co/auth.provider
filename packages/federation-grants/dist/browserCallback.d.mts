import type { RequestHandler } from "express";
import type { BrowserFlow } from "./browserFlow.mjs";
/**
 * Where the upstream returns the browser. Query mode only: a `form_post` callback
 * arrives without the session cookie, so check 3 could not run; boot refuses
 * such a federation.
 *
 * Check 1's failures are a plain 400: there is nowhere trustworthy to send the
 * browser. Every later failure redirects to the intent's `redirect_uri` with the
 * client's `state`, the `grant_id` and one `CallbackError` code, never an
 * upstream's description, a thrown message or anything the callback carried.
 */
export declare function createCallbackHandler(flow: BrowserFlow): RequestHandler;
//# sourceMappingURL=browserCallback.d.mts.map