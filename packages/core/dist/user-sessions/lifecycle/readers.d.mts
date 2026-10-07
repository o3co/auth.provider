/**
 * The one reading of what a `SessionLifecycleStore` answers, and of what a
 * caller hands one. A reader reads each property once and answers a fresh
 * frozen copy; anything outside the port's types is a TypeError naming the
 * field, which the caller treats as the store's outage. A check refuses a
 * caller's input outside the port's rules with a RangeError.
 */
import { type Versioned } from "../../adapters/conditionalWrite.mjs";
import { type SessionCloseAnswer, type SessionCloseRequest, type SessionJoinAnswer, type SessionLifecycleRecord, type SessionOpenAnswer, type SessionParticipant } from "./types.mjs";
/** The order of a listing: by the sids' UTF-8 bytes, so every store can keep it. */
export declare const compareSessionSids: (a: string, b: string) => number;
/** A store's answer to `open`. */
export declare function readSessionOpenAnswer(answer: SessionOpenAnswer): SessionOpenAnswer;
/** A store's answer to `join`. */
export declare function readSessionJoinAnswer(answer: SessionJoinAnswer): SessionJoinAnswer;
/** A store's answer to `read`: `null` when it holds no live record, else the record and its generation. */
export declare function readVersionedSessionLifecycle(answer: Versioned<SessionLifecycleRecord> | null): Versioned<SessionLifecycleRecord> | null;
/** A store's answer to `beginClose`: `missing`, or the record after the call, its state the outcome. */
export declare function readSessionCloseAnswer(answer: SessionCloseAnswer): SessionCloseAnswer;
/**
 * A store's answer to `listClosing(limit, after)`: at most `limit` sids, in
 * ascending order of their UTF-8 bytes, each after `after`.
 */
export declare function readSessionLifecycleListing(answer: readonly string[], limit: number, after?: string): readonly string[];
/** A participant the port admits, as a frozen copy; a RangeError otherwise. */
export declare function checkSessionParticipant(participant: SessionParticipant): SessionParticipant;
/** A close request the port admits, as a frozen copy; a RangeError otherwise. */
export declare function checkSessionCloseRequest(request: SessionCloseRequest): SessionCloseRequest;
/** A sid or sub the port admits: 1 to 512 UTF-16 code units, no lone surrogate; a RangeError otherwise. */
/** Whether `value` is a key the port admits: 1 to `SESSION_LIFECYCLE_MAX_KEY_LENGTH` characters, no lone surrogate. */
export declare function isSessionLifecycleKey(value: unknown): value is string;
export declare function checkSessionLifecycleKey(value: string, name: string): string;
/** A session's end the port admits: a `Date` with a finite time, copied; a RangeError otherwise. */
export declare function checkSessionExpiresAt(value: Date): Date;
/** A work item the port admits: a step name, or a participant's item; a RangeError otherwise. */
export declare function checkSessionCloseItem(value: string): string;
/** A listing's cursor the port admits: `""`, the start, or a key; a RangeError otherwise. */
export declare function checkSessionListingCursor(value: string): string;
/** A listing's limit the port admits: a whole number from 1 to 1000; a RangeError otherwise. */
export declare function checkSessionListingLimit(value: number): number;
//# sourceMappingURL=readers.d.mts.map