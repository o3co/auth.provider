/**
 * The JSON body parser of the package's ceremony routes, and the body reading
 * of the session admission in front of the registration routes, with the one
 * limit they share: 100kb, where a real WebAuthn payload is under 10KB. A
 * parser that finds the body already read leaves it as it is, so the routes
 * behind the admission do not read it twice. Internal to the package.
 */
import { type RequestHandler } from "express";
/** A parser of a JSON request body within the package's limit. */
export declare const jsonBody: () => RequestHandler;
/**
 * The body as the admission in front of the registration routes reads it:
 * to its end, whatever its framing, before anything after runs. A body read
 * before the provider's routes is judged as it was read. Otherwise a JSON
 * body is parsed as the routes parse it, and any other body is read within
 * the same limit and refused with `400 invalid_request` when it has bytes,
 * since the routes would not read it. A request with no body, or an empty
 * one, passes.
 */
export declare const wholeBody: () => RequestHandler[];
//# sourceMappingURL=jsonBody.d.mts.map