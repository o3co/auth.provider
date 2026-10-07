/**
 * The request and response the slot contract suites drive a component over,
 * without a server: the part of Express a component of these slots is held
 * to. A request carries headers, its own origin, a path, a parsed body and
 * an express session (`regenerate`, `save`, `sessionID`) whose regenerations
 * and saves are counted. A response records its status, body, headers and
 * cookies. A component that needs more of Express than this is outside the
 * contracts. Not on the kit's entry.
 */
import type { Request, RequestHandler, Response } from "express";
/** The origin every fake request is served on. */
export declare const CONTRACT_ORIGIN = "https://idp.contract.test";
/** What happened to a fake request's express session. */
export interface FakeSessionRecord {
    /** Successful regenerations. */
    regenerated: number;
    /** Successful saves. */
    saved: number;
    /** The session's own fields as it was last saved; `undefined` before the first save. */
    lastSaved: Readonly<Record<string, unknown>> | undefined;
}
export interface FakeRequestOptions {
    readonly method?: string;
    readonly path?: string;
    /** Header names are matched without regard to case, as Node's are. */
    readonly headers?: Readonly<Record<string, string>>;
    /** The parsed body, as a body parser leaves it; empty by default. */
    readonly body?: Readonly<Record<string, unknown>>;
    /** Every `regenerate` fails with this: an express-session store that is down. */
    readonly regenerateFails?: unknown;
    /** Every `save` fails with this. */
    readonly saveFails?: unknown;
}
/** A request with an anonymous express session, as express-session hands every request one. */
export declare function fakeRequest(options?: FakeRequestOptions): {
    readonly req: Request;
    readonly session: FakeSessionRecord;
};
/** What a fake response was told. */
export interface FakeResponseRecord {
    status: number | undefined;
    body: unknown;
    ended: boolean;
    readonly headers: Record<string, string>;
    readonly cookies: Array<{
        readonly name: string;
        readonly value: string;
        readonly options: Readonly<Record<string, unknown>> | undefined;
    }>;
    /** The names `clearCookie` was called with, in order. */
    readonly cleared: string[];
}
export declare function fakeResponse(): {
    readonly res: Response;
    readonly record: FakeResponseRecord;
};
/** Runs `middleware` over a request: whether it handed the request on, and what it answered. */
export declare function runMiddleware(middleware: RequestHandler, req: Request): Promise<{
    readonly next: number;
    readonly nextError: unknown;
    readonly response: FakeResponseRecord;
}>;
//# sourceMappingURL=fakeHttp.d.mts.map