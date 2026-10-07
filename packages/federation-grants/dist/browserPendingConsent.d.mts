/**
 * The consent question parked for this browser: the one reader behind `GET` and
 * `POST /consent`, so the page learns nothing on `GET` that the answer would then
 * refuse, and `GET /consent`'s data. A challenge with nothing behind it for this
 * browser, whatever the reason, gets the one indistinguishable answer. Every
 * `503` it answers is audited as `federation.grant.authorization_failed` with the
 * outcome `unavailable`, naming the flow only once its intent has been read.
 */
import { type FederationGrantIntent } from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import type { BrowserFlow } from "./browserFlow.mjs";
/**
 * The parked question, if this browser may see it — or `null` after an
 * answer has been sent. One reader for both methods, so that the page can
 * learn nothing on GET that the POST would then refuse.
 */
export declare const pendingFor: ({ options, now, log, admissionFor, failed }: BrowserFlow, req: Request, res: Response, challenge: unknown) => Promise<{
    consent: import("@o3co/auth-provider-core").FederationGrantConsentRecord;
    intent: FederationGrantIntent;
    binding: import("@o3co/auth-provider-core").FederationGrantBrowserBinding;
    challenge: string;
} | null>;
/** `GET /consent`: what the page shows the user, as data. */
export declare function createPendingConsentHandler(flow: BrowserFlow): RequestHandler;
//# sourceMappingURL=browserPendingConsent.d.mts.map