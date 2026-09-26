import type { RequestHandler, Response } from "express";
/** The header, in the spelling everything downstream reads it by. */
export declare const REQUEST_ID_HEADER = "x-request-id";
/**
 * The ID for this request: the caller's when it is usable, a fresh one
 * otherwise.
 *
 * `raw` is `req.headers[REQUEST_ID_HEADER]`, which Node types as
 * `string | string[] | undefined`. The array is the case worth naming: it is
 * what a stack that keeps duplicate occurrences apart produces, and no element
 * of it is a value *one* caller chose, so it is refused as a whole rather than
 * resolved by taking the first.
 */
export declare function resolveRequestId(raw: string | readonly string[] | undefined): string;
/**
 * Sets the ID on the response before anything else can answer, so that every
 * exit this package owns carries it — the disabled 404, a parser's 400, an
 * authentication challenge, a throttled 429 and the handlers alike.
 */
export declare function createRequestIdMiddleware(): RequestHandler;
/**
 * The ID this response is being answered under.
 *
 * Read back off the response rather than kept in a second place: the header is
 * already the one copy, it is set before anything can answer, and a handler
 * reading it cannot disagree with what the caller is told.
 */
export declare function requestIdOf(res: Response): string;
//# sourceMappingURL=requestId.d.mts.map