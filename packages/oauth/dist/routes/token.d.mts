/**
 * `POST /oauth/token`: dispatches on `grant_type` to the registered grant,
 * after the checks every grant inherits (the client's grant-type allowlist,
 * its sender constraint, a strict grant's deny-by-absence), and answers
 * RFC 6749 §5.1 or §5.2. It audits every issuance and refusal it answers.
 */
import { type AuditSink, type GrantHandlerResolver, type Logger } from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
import type { ResolvedOAuthOptions } from "../resolveOAuthOptions.mjs";
export declare const createTokenHandler: ({ registry, options, canonicalIssuer, auditSink, logger, }: {
    /** Where `grant_type` is looked up, per request. */
    readonly registry: Pick<GrantHandlerResolver, "get">;
    readonly options: Pick<ResolvedOAuthOptions, "requireGrantTypeAllowlist">;
    readonly canonicalIssuer: string;
    readonly auditSink: AuditSink | undefined;
    readonly logger: Logger;
}) => RequestHandler;
//# sourceMappingURL=token.d.mts.map