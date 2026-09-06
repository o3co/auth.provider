import type { ValidatedToken } from "./validator/types.mjs";
/**
 * Build the `act` claim for the token being issued, per RFC 8693 §4.1.
 *
 * Canonical rules:
 * - No actor_token → no `act` on the issued token (impersonation, no trace).
 *                    We do NOT inherit `subject.act`: absence of actor_token
 *                    means the caller is not claiming to delegate for anyone.
 * - Actor provided  → `act.sub = <actor.sub>`. If the subject already had an
 *                     `act` chain, it is nested as `act.act` to preserve the
 *                     full delegation history.
 */
export declare function buildActClaim(args: {
    subject: ValidatedToken;
    actor: ValidatedToken | undefined;
}): Record<string, unknown> | undefined;
//# sourceMappingURL=act.d.mts.map