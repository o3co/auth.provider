import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
export interface AuditEvent {
    readonly timestamp: Date;
    /**
     * Built-in event types (informative, not exhaustive):
     *   "login.success" | "login.failure" |
     *   "token.issued" | "token.refreshed" | "token.revoked" |
     *   "federation.success" | "federation.failure" |
     *   "mfa.challenge.issued" | "mfa.challenge.success" | "mfa.challenge.failure" |
     *   "logout" | "scope.denied" | "rate_limit.unavailable"
     * Consumers MAY emit custom event types with their own namespace.
     */
    readonly type: string;
    readonly subject?: string;
    readonly clientId?: string;
    readonly ip?: string;
    readonly userAgent?: string;
    readonly details?: Record<string, unknown>;
}
export interface AuditSinkBase {
    readonly kind: string;
    /**
     * Fire-and-forget recording. Implementations MAY buffer or batch internally.
     * Errors thrown here are swallowed by auth.provider core (audit failure
     * does NOT block auth flow).
     */
    record(event: AuditEvent): Promise<void>;
}
export type AuditSinkFactory = AdapterFactory<AuditSinkBase>;
//# sourceMappingURL=types.d.mts.map