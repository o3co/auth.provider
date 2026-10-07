/**
 * The fields `User` declares, each read by name however the object holds
 * it. An entry `User` does not declare fails to compile here, and a field
 * `User` declares that this list misses fails to compile below.
 */
declare const USER_FIELDS: readonly ["id", "username", "email", "emailVerified", "name", "picture", "groups", "mfaEnrolled"];
/** What `readUserSnapshot` answers: the snapshot, or why the `User` is refused. */
export type UserSnapshotReading = {
    readonly ok: true;
    readonly snapshot: Readonly<Record<string, unknown>> & {
        readonly id: string;
    };
} | {
    readonly ok: false;
    readonly refused: "not_an_object" | "id";
} | {
    readonly ok: false;
    readonly refused: "not_plain_data";
    readonly field: (typeof USER_FIELDS)[number];
};
/** What `readPlainFields` answers: the fields copied, or the first that is not plain data. */
export type PlainFieldsReading<F extends string> = {
    readonly ok: true;
    readonly copy: Readonly<Record<string, unknown>>;
} | {
    readonly ok: false;
    readonly field: F;
};
/**
 * `fields` of `record`, each read by name once — however the object holds
 * it: own data, an accessor, inherited, behind a Proxy — and copied as
 * plain data (`copyByName`), into one object frozen at every depth that
 * shares nothing with `record`. A field named twice is read once; one read
 * as `undefined` is left out; nothing else of `record` is read.
 *
 * Answers the first field holding what is not plain data. `record` is a
 * record, not a value: a field that refers back to it is not plain data,
 * and it is not read again. A read that throws is let through as it was
 * thrown.
 */
export declare function readPlainFields<F extends string>(record: object, fields: Iterable<F>): PlainFieldsReading<F>;
/**
 * The plain snapshot a login takes of `user`, its one read of it: each field
 * `User` declares, read by name, once, however the object holds it — own
 * data, an accessor, inherited, as a class instance or an ORM entity holds
 * it — and nothing else of it (`readPlainFields`). A field read as
 * `undefined` is left out. Frozen at every depth, sharing nothing with
 * `user`.
 *
 * Refused: a `user` that is not an object (`not_an_object`); a declared
 * field holding what is not plain data (`not_plain_data`, naming it), which
 * left out would read the witness as not enrolled; an `id` that is not a
 * non-empty string (`id`). The user is a record, not a value: a field that
 * refers back to it is not plain data, and it is not read again. A read
 * that throws is let through as it was thrown: never read as a witness or
 * an address.
 */
export declare function readUserSnapshot(user: unknown): UserSnapshotReading;
export {};
//# sourceMappingURL=userSnapshot.d.mts.map