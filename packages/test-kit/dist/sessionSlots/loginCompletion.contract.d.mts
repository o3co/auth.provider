import { type LoginCompletion } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
export interface LoginCompletionContractInput {
    /** A fresh completion for each case, over a session store that answers. */
    readonly build: () => LoginCompletion;
    /**
     * The completion over a session store that is down: establishing must
     * answer its outage at `create`. Absent for a completion that keeps no
     * session record.
     */
    readonly withSessionStoreOutage?: () => LoginCompletion;
    /**
     * How many session records the store holds that the completion built
     * last — by `build` or by `withSessionStoreOutage` — writes to: read after
     * the build, before and after a call. Absent for a completion whose
     * records the test cannot count.
     */
    readonly records?: () => number;
    /** The CSRF token's cookie, when the completion answers a `403` with a fresh token: set on the `403`, never on a `503`. */
    readonly csrfCookieName?: string;
}
/** The cases of the `loginCompletion` contract over the completion `input` builds. */
export declare function loginCompletionContract(input: LoginCompletionContractInput): readonly ContractCase[];
//# sourceMappingURL=loginCompletion.contract.d.mts.map