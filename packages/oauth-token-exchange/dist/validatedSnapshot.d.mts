/**
 * A validator's answer, read once into a plain, deeply frozen `ValidatedToken`
 * that every stage of the exchange reads instead of the answer, so a check
 * and the minted token cannot see two values of one member.
 *
 * What is copied, at each level: the members the stages read by name, own or
 * inherited, read whether or not `in` reports them, and kept whenever `in`
 * reports them (even with no value) or the read answers a value — the
 * answer's `sub`, `scope`, `aud`, `familyId`, `sid`, `act`, `may_act` and
 * `claims`; of `claims`, `azp`, `exp`, `iss`, `cnf` and `may_act`; of `cnf`,
 * the confirmation members (`jkt`, `x5t#S256`); of each `may_act` entry, `sub`
 * and `iss`; of each `act`, its nested `act` — and, below the answer itself,
 * every own enumerable key. So the copy holds every member a stage can read
 * off the answer, and is never looser than it. Where a stage reads a record
 * (the answer, `claims`, `cnf`, a `may_act` entry, `act`), an array is no
 * answer: an array's named members would not be copied. The copy holds plain
 * data only — strings, finite numbers, booleans, `null`, and arrays and
 * records of them — and a function (a `toJSON` included), a symbol, a bigint
 * or a number that is not finite in any copied position is no answer, so
 * nothing in the copy runs code when it is read or serialised. An array is
 * copied as a plain frozen array of its `length`, read once, which must be a
 * length an array can have (a whole number from 0 to 2^32 − 1), else no
 * answer; index by index, an index `in` does not report stays a hole, so the
 * copy holds no element native iteration of the answer would skip.
 *
 * `in` is asked once per object and member, and that one answer serves every
 * use. Actor matching in delegation tests a `may_act` entry's `sub` and `iss`
 * with `in`, while client matching reads `sub` by value; an entry reporting
 * neither to `in` is copied as a value that matches nothing. That is
 * conservative: it may refuse a client the entry's `sub` would have matched,
 * and never permits what the entry would refuse.
 *
 * A validator's answer is expected to be plain data. Of an answer whose
 * shape changes as it is read, the copy is the first read, and no more is
 * promised.
 *
 * Every member of an object is read at most once, however many paths reach
 * the object (an alias, a cycle): the reads are kept per object, and a copy
 * is registered before its members are copied. Every key is defined on the
 * copy as an own data property, so a key named `__proto__` is copied as a key
 * and never sets the copy's prototype. A read that throws propagates: the
 * caller answers it as the validator's outage. The authentication context the
 * built-in validator verified for the answer is carried to the copy.
 */
import type { ValidatedToken } from "@o3co/auth-provider-core";
import { type VerifiedAuthentication } from "./validator/selfIssuedAccessToken.mjs";
/**
 * Whether `answer` has the shape of an answer — a record (an object that is
 * not an array) with a string `sub` and record `claims` — reading those two
 * members once each and copying nothing. A read that throws propagates.
 */
export declare function isValidatedShape(answer: unknown): answer is ValidatedToken;
/**
 * The plain, frozen copy of `answer`, or `null` when it is no answer: not a
 * record, a `sub` that is not a string, `claims` that are not a record, or an
 * array where a record is read (`cnf`, a `may_act` entry, `act`).
 */
export declare function snapshotValidated(answer: unknown): ValidatedToken | null;
/**
 * The authentication context the built-in validator verified for the answer
 * `snapshot` was copied from, or `undefined` when another validator gave it.
 */
export declare function snapshotAuthentication(snapshot: ValidatedToken): VerifiedAuthentication | undefined;
//# sourceMappingURL=validatedSnapshot.d.mts.map