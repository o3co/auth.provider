/**
 * The template's security headers, on every response: helmet's defaults with
 * a Content-Security-Policy that allows nothing by default and no framing. A
 * route whose page needs more sets that response's own policy in place of
 * this one.
 */
import type { RequestHandler } from "express";
export declare function securityHeaders(): RequestHandler;
//# sourceMappingURL=securityHeaders.d.mts.map