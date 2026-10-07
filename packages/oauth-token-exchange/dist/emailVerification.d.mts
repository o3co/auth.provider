/**
 * The exchange's email gate under `oauth.requireEmailVerified`, the gate every
 * path that mints for a user applies. With the setting on, the user behind the
 * subject — the `sub` the issued token names — is read through
 * `userRepository.findBySubject`: a user the Store does not hold, or whose
 * email is not verified (core's `isEmailVerified`), is `invalid_request`, and a
 * read that throws is a 503. No subject is exempt: a subject that is a
 * client's (a `client_credentials` token's `sub`) names no user the Store
 * holds. Built with the setting on and no repository that can look a user
 * up, it throws, so the composition does not start. With the setting off,
 * nothing is read.
 */
import type { GrantDependencies, GrantHandlerResult, ProviderDeps } from "@o3co/auth-provider-core";
/** What the gate reads: the optional `userRepository` slot, and the logger an outage is reported on. */
export type EmailGateDependencies = Pick<GrantDependencies, "logger"> & ProviderDeps<never, "userRepository">;
/** The gate's answer for `subject`: the refusal, or `null` when the exchange may mint for it. */
export type EmailGate = (subject: string, clientId: string) => Promise<GrantHandlerResult | null>;
/**
 * The gate for a grant built under `requireEmailVerified`; one that reads
 * nothing when the setting is off. Throws when the setting is on and the
 * `userRepository` slot is unfilled or cannot answer `findBySubject`.
 */
export declare function emailGate(deps: EmailGateDependencies, requireEmailVerified: boolean): EmailGate;
//# sourceMappingURL=emailVerification.d.mts.map