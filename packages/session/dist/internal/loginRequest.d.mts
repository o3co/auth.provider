/**
 * What a login's primary authentication records of the request it arrived
 * on (the session-admission ADR's D5): the client address Express resolved
 * under the deployment's `trust proxy`, and the `User-Agent` — each only when
 * it is a string, as core's primary checks hold it. Both login paths build
 * their primary with it: `POST /session/login` (`routes/Session.mts`) and the
 * federation callback (`routes/Federation.mts`).
 */
import type { Request } from "express";
/** The request's `ip` and `User-Agent`, each present only when it is a string. */
export declare function loginRequestFacts(req: Request): {
    readonly ip?: string;
    readonly userAgent?: string;
};
//# sourceMappingURL=loginRequest.d.mts.map