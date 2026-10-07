import type { CsrfGuard, SessionCookiePolicy } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
export interface CsrfGuardContractInput {
    /** A fresh guard for each case, serving `https://idp.contract.test`. */
    readonly build: () => CsrfGuard;
    /** An origin the guard was built to trust beside its own, when it trusts one: accepted without a token. */
    readonly trustedOrigin?: string;
    /**
     * The guard over a clock the suite sets (epoch milliseconds), when the
     * provider takes one: a token past its lifetime must be refused. Absent,
     * expiry is not checked.
     */
    readonly withClock?: (now: () => number) => CsrfGuard;
    /** The session cookie the guard was built beside: the token's cookie is secure, same-site and scoped as it is. */
    readonly sessionCookie?: SessionCookiePolicy;
}
/** The cases of the `csrfGuard` contract over the guard `input` builds. */
export declare function csrfGuardContract(input: CsrfGuardContractInput): readonly ContractCase[];
//# sourceMappingURL=csrfGuard.contract.d.mts.map