/**
 * The session lifecycle port's rules for a caller's input, as the Redis store
 * applies them before it writes: each a RangeError, nothing written. Every
 * rule is core's, read through the checks and limits core exports: a sid, a
 * sub and a participant id share the port's one rule for a key, which core's
 * participant check holds an id to, and a work item is a step name (core's
 * close-request check) or a participant's item.
 */
import { type SessionCloseRequest, type SessionParticipant } from "@o3co/auth-provider-core";
/** `value` as the port's key: well-formed text of 1 to 512 UTF-16 code units. */
export declare function checkKey(value: string, name: string): string;
/** A participant the port admits, as core's frozen copy. */
export declare const checkParticipant: (participant: SessionParticipant) => SessionParticipant;
/** A close request the port admits, as core's frozen copy. */
export declare const checkCloseRequest: (request: SessionCloseRequest) => SessionCloseRequest;
/** A session's end: a `Date` with a valid time, read from its own time value. */
export declare function checkExpiresAt(value: Date): number;
/** A work item: a step name, or a participant's kind, a colon and its id. */
export declare function checkCloseItem(item: string): string;
/** A listing's limit: a whole number from 1 to the port's most. */
export declare function checkListingLimit(limit: number): number;
/** A listing's cursor: `""`, the start, or a key. */
export declare function checkListingCursor(after: string): string;
//# sourceMappingURL=session-lifecycle-input.d.mts.map