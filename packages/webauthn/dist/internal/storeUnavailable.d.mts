/**
 * How this package answers a store that cannot answer, shared by the grant and
 * the three ceremony routes: `503 temporarily_unavailable`, with a description
 * naming the kind of store, and one error line carrying the error's
 * projection — never the error, which can carry what the store was sent. The
 * routes log it here as `webauthn_ceremony_store_unavailable`; the grant logs
 * its own `webauthn_grant_store_unavailable` and uses the descriptions.
 * Internal to the package.
 */
import { type Logger } from "@o3co/auth-provider-core";
import type { Response } from "express";
/** Which store could not answer, as the log line names it. */
export type WebAuthnStore = "webauthn_credential" | "challenge" | "challenge_ceremony" | "refresh_token_family";
/** The `error_description` a 503 for `store` carries. */
export declare const storeUnavailableDescription: (store: WebAuthnStore) => string;
/** Where a ceremony route's store call failed. */
export interface CeremonyStoreFailure {
    readonly site: "registration_options" | "registration_verify" | "authentication_options";
    readonly store: Exclude<WebAuthnStore, "refresh_token_family">;
    readonly step: "list" | "issue" | "consume" | "register";
}
/**
 * Answer a ceremony route's store outage: one error line,
 * `webauthn_ceremony_store_unavailable`, then `503 temporarily_unavailable`.
 */
export declare function refuseCeremonyStoreUnavailable(res: Response, logger: Pick<Logger, "error">, failure: CeremonyStoreFailure, cause: unknown): void;
//# sourceMappingURL=storeUnavailable.d.mts.map