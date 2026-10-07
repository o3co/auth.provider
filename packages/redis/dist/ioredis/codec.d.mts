/**
 * The values the wrappers exchange with the scripts: a number as a Redis argument, and a reply
 * as the client contract's fields. A reply of any other shape reads as no fields or no value;
 * none of these throws.
 */
import type { DeviceCodeRecordFields, FederationGrantHashFields } from "../clients.mjs";
/**
 * `HGETALL`'s flat `[field, value, …]` reply — as a script returns it — as
 * the hash's fields. Anything but a list is no fields. The one reading of
 * that reply, shared by every store here that has a script answer a hash.
 */
export declare const hashFields: (flat: unknown) => Record<string, string>;
/** `HGETALL`'s flat `[field, value, …]` reply as the record's fields. */
export declare const deviceCodeRecordOf: (flat: unknown) => DeviceCodeRecordFields;
/**
 * A number as a Redis argument, rounded to an integer. Plain digits for a magnitude below 1e21;
 * at or above it `toFixed` gives exponent form, and a non-finite value is spelled out.
 */
export declare const fgNumber: (value: number) => string;
/** `HGETALL`'s flat `[field, value, …]` reply as the record's fields. */
export declare const fgFields: (flat: unknown) => FederationGrantHashFields;
/**
 * A write's reply: `[1, fields]` when it happened, `[0]` when it was refused.
 * Absence and a failed precondition are the same answer on purpose: the
 * record may change again before the caller looks, so the port re-reads.
 */
export declare const fgWritten: (reply: unknown) => FederationGrantHashFields | null;
export declare const fgiText: (reply: unknown) => string | null;
//# sourceMappingURL=codec.d.mts.map