/**
 * Who may ask `/oauth/introspect`: a caller whose credential is its own
 * access token (Bearer or DPoP) may ask about that token alone, once it
 * verifies; any other caller must pass the client authentication the router
 * built for this endpoint.
 */
import { type AccessTokenDenylist, type AuditSink, type KeyStore, type Logger, type SubjectRevocation } from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
export declare const createIntrospectCallerCheck: ({ keyStore, canonicalIssuer, accessTokenDenylist, subjectRevocation, introspectClientAuthMw, auditSink, logger, }: {
    readonly keyStore: KeyStore;
    readonly canonicalIssuer: string;
    readonly accessTokenDenylist: AccessTokenDenylist | undefined;
    readonly subjectRevocation: SubjectRevocation | undefined;
    /** What a caller without its own access token as the credential must pass. */
    readonly introspectClientAuthMw: RequestHandler;
    readonly auditSink: AuditSink | undefined;
    readonly logger: Logger;
}) => RequestHandler;
//# sourceMappingURL=introspectCaller.d.mts.map