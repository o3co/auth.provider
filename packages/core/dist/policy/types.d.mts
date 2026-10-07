import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
export interface GrantPolicyRequest {
    readonly grantType: string;
    readonly clientId?: string;
    readonly subject?: string;
    readonly requestedScope?: readonly string[];
    readonly requestedAudience?: readonly string[];
    readonly originalScope?: readonly string[];
    readonly subjectTokenType?: string;
    readonly actorTokenType?: string;
    readonly resource?: readonly string[];
    readonly extras?: Record<string, unknown>;
}
export interface GrantPolicyContext {
    readonly ip?: string;
    readonly userAgent?: string;
    readonly issuer: string;
}
export type GrantPolicyDecision = {
    readonly outcome: "allow";
    readonly grantedScope?: readonly string[];
    readonly grantedAudience?: readonly string[];
} | {
    readonly outcome: "deny";
    readonly error: string;
    readonly errorDescription?: string;
};
export interface GrantPolicyHookBase {
    readonly kind: string;
    evaluate(request: GrantPolicyRequest, ctx: GrantPolicyContext): Promise<GrantPolicyDecision>;
}
export type GrantPolicyHookFactory = AdapterFactory<GrantPolicyHookBase>;
//# sourceMappingURL=types.d.mts.map