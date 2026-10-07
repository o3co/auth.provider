/**
 * Issuing the code (RFC 6749 §4.1.2): the audience it carries (RFC 8707 §2),
 * the code record, which alone carries the identity binding and how the
 * session had authenticated when the code was issued (`acr`, `amr`,
 * `authentication`), and the redirect that delivers it with `state` and the
 * `authorize.granted` audit event.
 */
import { type Admission, type PublicClient } from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { AuthorizeContext } from "./authorizeContext.mjs";
/**
 * RFC 8707 §2 audience shaping for the code record, or `null` when the
 * requested resources cannot be represented and a response has been sent.
 */
export declare const resolveAudienceForPersist: (ctx: AuthorizeContext, client: PublicClient, authorizeResource: readonly string[] | null, grantedAudience: readonly string[] | undefined) => {
    audienceForPersist: readonly string[] | undefined;
} | null;
/**
 * RFC 6749 §4.1.2 code issuance, or `null` after a `temporarily_unavailable`
 * redirect: a code store that cannot answer is the condition §4.1.2.1 names
 * `temporarily_unavailable` for, not `server_error`. Logged once at error
 * level as `authorize_store_unavailable`.
 */
export declare const mintCode: (ctx: AuthorizeContext, params: {
    codeChallenge: string | undefined;
    codeChallengeMethod: string | undefined;
    grantedScope: readonly string[] | undefined;
    grantedAudience: readonly string[] | undefined;
    /** The `acr` the session met. */
    acr: string | undefined;
    /** What admission read of how the session had authenticated: the code's `amr` and `authentication`. */
    codeFields: Extract<Admission, {
        readonly outcome: "admitted";
    }>["codeFields"];
}) => Promise<{
    code: string;
} | null>;
export declare const redirectWithCode: (ctx: AuthorizeContext, code: string) => Promise<Response>;
//# sourceMappingURL=authorizeIssuance.d.mts.map