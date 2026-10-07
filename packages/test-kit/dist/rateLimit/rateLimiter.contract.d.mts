import { type RateLimiter, type RateLimitSpec } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
export interface RateLimiterContractInput {
    /** A fresh limiter for each case, over a backend that answers. */
    readonly build: () => RateLimiter;
    /** The limiter over a backend that is down: `check` must reject. Absent for a limiter with no backend of its own. */
    readonly withOutage?: () => RateLimiter;
    /** The limiter applying `spec` to every key. Absent for a limiter that takes no spec. */
    readonly withBudget?: (spec: RateLimitSpec) => RateLimiter;
}
/** The cases of the `RateLimiter` contract over the limiters `input` builds. */
export declare function rateLimiterContract(input: RateLimiterContractInput): readonly ContractCase[];
//# sourceMappingURL=rateLimiter.contract.d.mts.map