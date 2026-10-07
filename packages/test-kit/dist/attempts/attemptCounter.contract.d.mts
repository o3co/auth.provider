import { type AttemptCounter } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
/** What one case runs over. */
export interface AttemptCounterHarness {
    readonly counter: AttemptCounter;
    /**
     * The same backend through a second instance: another connection, pool or
     * client. Absent: `counter` again, with no cross-process proof.
     */
    readonly second?: AttemptCounter;
    /**
     * The counter's clock, which the harness moves by hand. Absent: the
     * counter reads the real clock, and the window cases wait in real time.
     */
    readonly clock?: {
        /** Epoch milliseconds, as the counter reads them. */
        now(): number;
        advance(ms: number): void | Promise<void>;
    };
    /** A counter over the same backend that cannot reach it. */
    readonly unreachable?: () => AttemptCounter;
    readonly close?: () => Promise<void>;
}
export interface AttemptCounterContractInput {
    readonly build: () => Promise<AttemptCounterHarness>;
    /**
     * The hooks every harness `build` answers, declared up front, so the case
     * list is fixed when the suite is built. A declared hook that a harness
     * lacks fails its case; an undeclared one runs no case, and one passing
     * case names what was not run.
     */
    readonly supports?: {
        readonly unreachable?: boolean;
    };
}
/** How far a counter on the real clock may place a window's end from where the suite expects it. */
export declare const REAL_CLOCK_TOLERANCE_MS = 1000;
/** The cases of the `AttemptCounter` contract over the harnesses `input` builds. */
export declare function attemptCounterContract(input: AttemptCounterContractInput): readonly ContractCase[];
//# sourceMappingURL=attemptCounter.contract.d.mts.map