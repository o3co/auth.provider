/**
 * How `/authorize` answers: the login-page redirect (also sent by the login
 * check, before any lookup) and, once `redirect_uri` is validated, an error on
 * it with `state` (RFC 6749 §4.1.2.1) and the `authorize.rejected` audit event.
 * Until then, the client stage answers JSON itself.
 */
import { type LoginEntry } from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { AuthorizeContext } from "./authorizeContext.mjs";
/** The login-page redirect with the request to come back to. */
export declare const loginRedirect: (res: Response, login: Pick<LoginEntry, "urlFor">, target: string) => void;
export declare const redirectError: (ctx: AuthorizeContext, error: string, errorDescription: string) => Response;
/**
 * Emits `authorize.rejected`, with the payload shape of the token endpoint's
 * `token.issued.failure`; the success event is `authorize.granted`.
 */
export declare const auditFailure: (ctx: AuthorizeContext, details: Record<string, unknown>) => Promise<void>;
//# sourceMappingURL=authorizeAnswers.d.mts.map