/**
 * Spread the optional `reason` of a `RefreshTokenFamilyUpdateDecision` onto a
 * `RefreshTokenFamilyUpdateResult`, omitting the key entirely when the
 * decision carried none.
 *
 * ```ts
 * return { outcome: "aborted", ...withReason(decision.reason) };
 * ```
 *
 * Why this exists rather than `reason: decision.reason` at each call site:
 * `reason` is declared OPTIONAL, and an unconditional assignment puts the key
 * on the object holding `undefined`. "Absent" and "present but `undefined`"
 * are then indistinguishable to the contract but distinguishable to every
 * consumer — `"reason" in result`, `Object.keys`, `toStrictEqual`, and any
 * serialisation of the result all disagree with each other about which one
 * happened. An adapter that always writes the key silently contradicts the
 * interface it implements.
 *
 * Why it is EXPORTED rather than inlined twice: the in-memory and Redis
 * adapters must be substitutable down to the shape of what they return, which
 * is the premise that lets the rotation ceremony live in one shared wrapper
 * instead of being reimplemented per backend (A3 §5.1). Two hand-written
 * copies of the same conditional spread is exactly the kind of parity that
 * decays on the next edit, so both call it, and so should any third-party
 * `RefreshTokenFamilyStore`.
 *
 * Per A3 §5.1 + #274.
 */
export declare const withReason: (reason: string | undefined) => {
    reason?: string;
};
//# sourceMappingURL=reason.d.mts.map