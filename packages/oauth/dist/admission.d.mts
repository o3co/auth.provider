/**
 * The token endpoint's `step_up` refusal, shared by every consumer of session
 * admission in this package (see ADR 2026-09-28-session-admission):
 * `invalid_grant` with one member beside RFC 6749's, `step_up:
 * "<requirement>"`. The `session`, `authorization_code` and `refresh_token`
 * grants answer it and `/oauth/token` copies it onto the wire. A hand-built
 * factory's missing or forged requirements resolver is refused by core's
 * `checkResolver(value, factory)`, which every consumer factory runs at
 * construction.
 */
import type { GrantError } from "@o3co/auth-provider-core";
/** The token endpoint's `step_up` refusal: `invalid_grant`, and the requirement that asked, so an updated client can offer the step-up. */
export interface StepUpRefusal extends GrantError {
    readonly status: 400;
    readonly error: "invalid_grant";
    readonly errorDescription: string;
    /** The member `/oauth/token` copies onto the body beside `error` and `error_description`. */
    readonly step_up: string;
}
/**
 * A `step_up` admission as a grant answers it: the session is live and
 * a requirement can be met by a trip a token endpoint cannot send anyone on,
 * so the client re-authenticates the user interactively — `invalid_grant`,
 * with the requirement named in `step_up`.
 */
export declare const stepUpRefusal: (requirement: string) => StepUpRefusal;
/** The `step_up` member of a grant's error, when it carries one. */
export declare const stepUpOf: (result: GrantError) => string | undefined;
//# sourceMappingURL=admission.d.mts.map