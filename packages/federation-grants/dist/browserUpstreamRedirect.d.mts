/**
 * An accepted consent sent upstream: the delegated authorization URL is built with
 * a fresh `state`, `nonce` and PKCE verifier before the answer is recorded, so a
 * configuration fault spends no consent, and the browser is redirected only once
 * the store holds the transaction.
 */
import type { FederationGrantIntent, FederationGrantIntentStore } from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { BrowserFlow } from "./browserFlow.mjs";
/** Records the answer; `null` after the `503` it gave. */
export type RecordAnswer = (answer: Parameters<FederationGrantIntentStore["answerConsent"]>[0]["answer"]) => Promise<Awaited<ReturnType<FederationGrantIntentStore["answerConsent"]>> | null>;
/** Gives the answer's `503`, writes its one line and audits it. */
export type ConsentUnavailable = (description: "storage" | "upstream_unavailable", at: {
    readonly store?: string;
    readonly step: string;
    readonly refusal?: string;
}, ...cause: [] | [unknown]) => void;
export declare function redirectUpstream({ options, randomId }: BrowserFlow, res: Response, intent: FederationGrantIntent, record: RecordAnswer, consentUnavailable: ConsentUnavailable): Promise<void>;
//# sourceMappingURL=browserUpstreamRedirect.d.mts.map