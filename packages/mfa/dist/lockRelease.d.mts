/**
 * `POST /session/mfa/lock/release`: the signed-in subject's own release of
 * its MFA lock, mounted from `routes.mts` behind its `no-store`, body
 * parsing, CSRF and flood guards, the session admitted as `mfa.manage`
 * through `routes.mts` first. What is released, and when, is
 * `lockRecovery.mts`'s; this file answers what it came to.
 *
 * - `200 {"lock":"released"}`: given back — or given back before, on the
 *   same authorization.
 * - `200 {"lock":"held","hold":"hard"}` with a description and
 *   `rebind_after`: the week and the backoff may be given back, but
 *   guessable factors stay held until each is replaced after
 *   `rebind_after`; the page says so, never "released". Replacing them
 *   first, then releasing, spends one exempt proof.
 * - `403 mfa_exempt_proof_required`: no authorization stands in this
 *   session — a recovery code or a passkey verifies one.
 * - `409 mfa_lock_release_refused` with `reason`: `not_revoked_since`, no
 *   revocation of the subject's sessions since the attack began — the page
 *   asks for a password change; `no_revocation_boundary`, none can be read
 *   here — while the hard hold stands, a rebind alone lifts it, and the
 *   description says so. Either carries `rebind_after` while the hard hold
 *   stands.
 * - `rebind_after` is from when a rebind counts, in ISO 8601 as
 *   `created_at` is in `GET /factors`: shown to the account holder, never
 *   logged.
 * - `409 mfa_factors_busy` with `Retry-After`; `503` for an outage, logged
 *   once at error.
 * - Logged `mfa_lock_released`, `mfa_lock_release_held` (the hard hold
 *   stands) and `mfa_lock_release_refused` at info; an
 *   authorization applied now is audited `mfa.lock.recovered` with the
 *   operation, the generation and what it cleared.
 */
import { type AuditSink, type Logger } from "@o3co/auth-provider-core";
import { type Request, type Response, type Router } from "express";
import type { MfaCeremonySession } from "./ceremony.mjs";
import type { MfaLockRecovery } from "./lockRecovery.mjs";
export interface MfaLockReleaseOptions {
    readonly lockRecovery: Pick<MfaLockRecovery, "release">;
    /** The signed-in session the request's cookie carries, admitted as `mfa.manage`; `undefined` once the refusal is answered. */
    readonly admit: (req: Request, res: Response) => Promise<MfaCeremonySession | undefined>;
    readonly logger: Logger;
    readonly auditSink: AuditSink | undefined;
}
/** The release's router (see this file's header). */
export declare function createMfaLockReleaseRouter(options: MfaLockReleaseOptions): Router;
//# sourceMappingURL=lockRelease.d.mts.map