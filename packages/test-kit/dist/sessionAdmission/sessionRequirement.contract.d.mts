import { type PrimaryAuthentication, type SessionRequirement } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
export interface RequirementContractInput {
    /** The key the requirement is contributed under. */
    readonly key: string;
    /** Whether the requirement under test is a fixture: a fixture never declares the second-factor authority. */
    readonly fixture: boolean;
    /**
     * The issuer its page is registered on, as boot registers it on
     * `oauth.jwt.issuer`. When absent, an absolute page is held to its shape
     * alone and a path page is refused, so every case fails: pass the issuer
     * for a requirement whose page is a path.
     */
    readonly issuer?: string;
    /** A fresh requirement for each case, so no case sees another's state. */
    readonly build: () => SessionRequirement;
    /** The requirement built over a dependency that is down: its `admit` must throw. Absent when it has none. */
    readonly withOutage?: () => SessionRequirement;
    /** A primary its `admitPrimary` may interrupt (built by `passwordPrimary`). Absent when it never interrupts a login. */
    readonly primary?: PrimaryAuthentication;
}
/** The contract's cases over the requirement `input` describes. */
export declare function sessionRequirementContract(input: RequirementContractInput): readonly ContractCase[];
//# sourceMappingURL=sessionRequirement.contract.d.mts.map