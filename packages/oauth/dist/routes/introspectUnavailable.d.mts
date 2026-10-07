/**
 * How `/oauth/introspect` answers when a store it needs did not answer: `503`,
 * never RFC 7662 §2.2's `active: false`, which is a verdict on the token.
 * Each such answer is audited as `introspect.store_unavailable`.
 */
import { type AuditSink, type Logger } from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import { refuseVerificationUnavailable } from "../verificationUnavailable.mjs";
/** The answers, reported through the router's audit sink and logger. */
export declare const createIntrospectUnavailableAnswers: ({ auditSink, logger, }: {
    readonly auditSink: AuditSink | undefined;
    readonly logger: Logger;
}) => {
    answerIntrospectionUnavailable: (req: Request, res: Response, err: Parameters<typeof refuseVerificationUnavailable>[1]) => Response;
    answerStoreUnavailable: (req: Request, res: Response, outage: {
        readonly store: "refresh_token_family" | "user_session";
        readonly details: Readonly<Record<string, string>>;
        readonly cause: unknown;
    } | {
        readonly store: "session_lifecycle";
        readonly details: Readonly<Record<string, string>>;
        /** Present when the lifecycle rejected; absent for the defensive fallback on any other answer. */
        readonly cause?: unknown;
    }) => Response;
};
//# sourceMappingURL=introspectUnavailable.d.mts.map