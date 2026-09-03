import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
export interface RateLimitContext {
    readonly ip?: string;
    readonly userAgent?: string;
    readonly clientId?: string;
    readonly userId?: string;
}
export interface RateLimitDecision {
    readonly allowed: boolean;
    readonly remaining?: number;
    readonly resetAt?: Date;
    readonly reason?: string;
}
export interface RateLimiterBase {
    readonly kind: string;
    /**
     * Atomic check + increment. Key is endpoint-specific (e.g.,
     * "login:ip:1.2.3.4", "token:client:abc").
     */
    check(key: string, ctx: RateLimitContext): Promise<RateLimitDecision>;
}
export type RateLimiterFactory = AdapterFactory<RateLimiterBase>;
/**
 * Rate-limit spec, e.g., `{ limit: 10, windowSeconds: 60 }`. Consumed by
 * built-in adapters; custom adapters may interpret the config freely.
 */
export interface RateLimitSpec {
    readonly limit: number;
    readonly windowSeconds: number;
}
//# sourceMappingURL=types.d.mts.map