import type { SessionEnrollmentFacts } from "./types.mjs";
/**
 * `value` as `SessionEnrollmentFacts`: a new object holding its two fields
 * when it is one, else `undefined`. Each field is read once; a read that
 * throws is no value.
 */
export declare function readEnrollmentFacts(value: unknown): SessionEnrollmentFacts | undefined;
/**
 * What a store records as a session's `enrollmentFacts`: `undefined` for
 * none, else a copy of the two facts. Every bundled store's `create` records
 * this answer, never its own input, so both refuse the same values.
 *
 * @throws RangeError naming the session, quoting nothing of the value, for
 *   anything else.
 */
export declare function recordableEnrollmentFacts(sid: string, value: unknown): SessionEnrollmentFacts | undefined;
//# sourceMappingURL=enrollmentFacts.d.mts.map