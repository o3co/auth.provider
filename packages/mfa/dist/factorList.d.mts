/**
 * What `MfaFactorStore.list` answered, read as a list of records: the one
 * reading every read of the list in this package goes through, but the
 * operator reset's snapshot of what it removes (`factorSet.mts`), which only
 * counts for its report and reads the list as listed.
 *
 * The answer must be an array, every entry an own element that is an object
 * with a string `kind` — the field every judgment over the records keys on.
 * Anything else throws — a `TypeError`, or what reading an entry's `kind`
 * threw — the store's fault, which each caller answers as the store's
 * outage: a hole or an entry that is not a record would otherwise be
 * skipped, or read as a kind it is not, and the subject read as holding
 * fewer factors than the store holds. An empty list is a subject with none.
 * The rest of a record's fields are read where they are used.
 */
import type { MfaFactorRecord } from "@o3co/auth-provider-core";
/** `answer` as a fresh array of the records it holds; throws for anything but a list of records. */
export declare function readFactorList(answer: unknown): MfaFactorRecord[];
//# sourceMappingURL=factorList.d.mts.map