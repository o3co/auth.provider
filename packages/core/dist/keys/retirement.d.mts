/**
 * Reads each previous key's retirement date as epoch milliseconds, refusing
 * one that is not a Date holding a valid time. `dates` names each by where it
 * was configured (`previousKeys[0].expiresAt`); the message names that place
 * and what is wrong, never the value.
 */
export declare function readRetirementTimes(owner: string, dates: ReadonlyArray<readonly [where: string, expiresAt: unknown]>): number[];
/**
 * Whether a key retiring at `retiresAt` still verifies at `now`, both epoch
 * milliseconds: only strictly before it. A time that cannot be compared
 * counts as passed.
 */
export declare const verifiesBefore: (retiresAt: number, now: number) => boolean;
//# sourceMappingURL=retirement.d.mts.map