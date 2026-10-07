import type { DeviceAuthorization } from "./types.mjs";
/** What `readDeviceAuthorization` answers: the copy, or why the record is refused. */
export type DeviceAuthorizationReading = {
    readonly ok: true;
    readonly authorization: DeviceAuthorization;
} | {
    readonly ok: false;
    readonly refused: "not_an_object";
} | {
    readonly ok: false;
    readonly refused: "malformed";
    readonly field: keyof DeviceAuthorization;
};
/**
 * `record` read into a `DeviceAuthorization`: each declared field read by
 * name, once, however the object holds it — own data, an accessor,
 * inherited, a class instance — and nothing else of it. The copy has every
 * key, `undefined` where the record holds none, and is frozen at every depth,
 * sharing nothing with `record`.
 *
 * Refused: a `record` that is not an object, or whose shape cannot be
 * checked (`not_an_object`); a field whose
 * read throws or whose value is not what the type declares (`malformed`,
 * naming it). A scope is a list of RFC 6749 §3.3 scope-tokens. An expiry is
 * held to `isStorableExpiry`; an approval instant and an authentication time
 * to whole epoch milliseconds at or after the epoch that a `Date` holds, as
 * `recordableDeviceApproval` records one. Neither is read against a clock
 * here: that is the consumer's. An `amr` that is not a non-empty list of non-empty strings, or cannot be
 * read, is read as none rather than refused.
 */
export declare function readDeviceAuthorization(record: unknown): DeviceAuthorizationReading;
//# sourceMappingURL=reading.d.mts.map