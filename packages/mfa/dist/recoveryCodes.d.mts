/**
 * `POST /session/mfa/recovery-codes`: the signed-in subject's regeneration of
 * its recovery codes, mounted from `routes.mts` behind its `no-store`, body
 * parsing, CSRF and flood guards, the session admitted as `mfa.manage`
 * through `routes.mts` first, with where its factor-set write begins. What a
 * new set replaces, and how, is `recovery/issue.mts`'s; the lease is
 * `factorSet.mts`'s; this file answers what it came to.
 *
 * - `200 {"recovery_codes": [...]}`: the new set's codes, answered once — the
 *   set bound by `mfa`, and every set that stood retired and removed —
 *   audited `mfa.recovery_codes.generated` (`by: "user"`, `binding: "mfa"`,
 *   `regenerated`, and `unreplaced: true` when a retired set is left stored,
 *   said once at error). Codes marked shown are answered whatever else the
 *   write came to: a lease that ended before its release is said at error.
 * - `409 mfa_enrollment_required`: no record that may count stands, so
 *   admission took the session on a recent primary; codes are issued beside a
 *   counting factor only.
 * - `401 login_required` with `Retry-After`: the subject's first-binding mark
 *   (`firstBindingMark.mts`), read under the lease, distrusts the session's
 *   sign-in — one made before a first binding, which admission may have taken
 *   on a recent primary while no factor stood; said at info
 *   (`mfa_first_binding_distrusted`). A mark that cannot be read is `503`.
 *   The mark distrusts up to the skew and one lease after it, as every
 *   reader of it does — the owner's factor may land up to a lease after its
 *   mark, and a sign-in in that stretch on a clock up to the skew ahead must
 *   not pass. Every mark distrusts, so it also refuses,
 *   until the sign-in is later than the mark plus the skew and a lease: the session that bound the first
 *   factor (it got codes then), one whose login reconciled the witness, one
 *   signed in before a binding and stepped up after it, and a fresh MFA login
 *   on another device within the skew; a step-up in a session whose witness
 *   is not `enrolled` notes the mark again, and so arms it again. The mark is
 *   used because admission's verdicts cannot say "met only on recent MFA,
 *   else enrollment required" for one action, and the route may not read the
 *   session record's `mfaAt` beside admission's view.
 * - `409 mfa_request_stale`: the request reached its lease longer after it
 *   began than a mark can be relied on — its lifetime less the skew and a
 *   lease — so a mark noted meanwhile may have lapsed; nothing written.
 * - `409 mfa_factor_limit`: the set would take the subject past
 *   `mfa.maxFactorsPerSubject` (`recordsAfterRecoveryCodes`: replacing a set
 *   at the limit stays allowed); nothing written.
 * - `409 mfa_recovery_codes_conflict`: the subject's factor set changed
 *   after the lease read it — another write landed, which only a writer past
 *   its own lease can make — so the new set was not written, the floor not
 *   raised, and no codes answered (warn).
 * - `409 mfa_factors_busy` with `Retry-After`; `409 mfa_factors_changed` for a
 *   recovery or a reset since the request was admitted, nothing written.
 * - `400` while the recovery-code factor is off, before any lease; `503` for
 *   an outage — the codes not answered, the set left unshown — logged once at
 *   error.
 */
import { type AuditSink, type Logger, type MfaFactorResolver } from "@o3co/auth-provider-core";
import { type Request, type Response, type Router } from "express";
import type { MfaFactorSet } from "./factorSet.mjs";
import { type FirstBindingMark } from "./firstBindingMark.mjs";
import type { MfaManagingSession } from "./management.mjs";
import type { MfaSealing } from "./sealing.mjs";
export interface MfaRecoveryCodesOptions {
    readonly factors: MfaFactorResolver;
    /** The subject's writes under its lease. */
    readonly factorSet: MfaFactorSet;
    readonly sealing: MfaSealing;
    /** The signed-in session the request's cookie carries, admitted as `mfa.manage`; `undefined` once the refusal is answered. */
    readonly admit: (req: Request, res: Response) => Promise<MfaManagingSession | undefined>;
    readonly logger: Logger;
    readonly auditSink: AuditSink | undefined;
    /** `mfa.maxFactorsPerSubject`. */
    readonly maxFactorsPerSubject: number;
    /** The subject's first-binding mark (`MfaTransactionStore.firstBindingAt`), read under the lease. */
    readonly firstBindingAt: (subject: string, nowMs: number) => Promise<unknown>;
    /** The first-binding mark as every reader judges it (`createFirstBindingMark`). */
    readonly firstBindingMark: FirstBindingMark;
    /** The clock, in epoch milliseconds. Defaults to `Date.now`. */
    readonly now?: () => number;
}
/** The regeneration route's router (see this file's header). */
export declare function createMfaRecoveryCodesRouter(options: MfaRecoveryCodesOptions): Router;
//# sourceMappingURL=recoveryCodes.d.mts.map