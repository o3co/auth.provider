import type { SubjectWriter } from "../contract.ts";

/**
 * The subject writer: the manifest's `takenBy` keeps this entry for `subject-records` alone. One
 * frozen value of this module, matched by its identity, never by a name: a copy of it is another
 * value, and refused.
 */
export const subjectWriter = Object.freeze({}) as SubjectWriter;
