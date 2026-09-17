import { type AuditSink, type ClientRepository, type ConsentStore, type Logger, type PendingConsentStore, type UserSessionStore } from "@o3co/auth-provider-core";
import type { RequestHandler, Router } from "express";
export declare const PENDING_CONSENT_TTL_MS: number;
export declare const newConsentChallenge: () => string;
type ExpressLike = {
    Router: () => Router;
    json: () => RequestHandler;
    urlencoded: (opts: {
        extended: boolean;
    }) => RequestHandler;
};
export interface ConsentRouterOptions {
    readonly consentStore: ConsentStore;
    /** #552: where `/authorize` parked the request; the answer consumes it. */
    readonly pendingConsentStore: PendingConsentStore;
    readonly clientRepository: ClientRepository;
    /**
     * #527 review: the durable session behind the cookie. `/authorize`
     * re-reads it before it mints anything, and these endpoints must too —
     * a session revoked out of band while the browser still holds its cookie
     * and its parked challenge would otherwise record a consent that a later
     * login then inherits without ever being asked.
     */
    readonly userSessionStore?: UserSessionStore;
    readonly auditSink?: AuditSink;
    readonly logger: Logger;
}
export declare function createConsentRouter(express: ExpressLike, opts: ConsentRouterOptions): Router;
export {};
//# sourceMappingURL=consent.d.mts.map