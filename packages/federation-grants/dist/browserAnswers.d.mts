/**
 * How the browser flow answers: plain text for a navigation, `/oauth/consent`'s
 * error shape for the consent page, nothing cached and no referrer on any
 * response, and a return to the client carrying only the grant, the client's
 * `state` and one fixed error code.
 */
import type { FederationGrantIntent } from "@o3co/auth-provider-core";
import type { RequestHandler, Response } from "express";
export declare const noStoreNoReferrer: RequestHandler;
/** A navigation's refusal: plain text, never a JSON body a user would see raw. */
export declare const plain: (res: Response, status: number, message: string) => void;
/** The page's refusal, in `/oauth/consent`'s shape. */
export declare const jsonError: (res: Response, status: number, error: string, description: string) => void;
/**
 * One answer for every challenge with nothing behind it — answered, expired,
 * never issued, issued to another browser — so the response does not say
 * which. The sibling's wording, for the page that already handles it.
 */
export declare const NO_PENDING = "no pending consent for this challenge: it was answered, has expired, or was not issued to this session; start again";
/** Where a declined flow ends: the client's own URI, with what it needs and nothing else. */
export declare function clientReturn(intent: FederationGrantIntent, error?: string): string;
/**
 * What a failed callback sends back to the client, and nothing else.
 * `identity_unverifiable` is not `temporarily_unavailable`: asking again will not
 * change it.
 */
export type CallbackError = "access_denied" | "reauthentication_required" | "account_mismatch" | "identity_conflict" | "identity_unverifiable" | "refresh_token_absent" | "upstream_token_ineligible" | "scope_exceeded" | "upstream_error" | "temporarily_unavailable" | "grant_not_authorizable";
//# sourceMappingURL=browserAnswers.d.mts.map