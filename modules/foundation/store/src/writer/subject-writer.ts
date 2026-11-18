import type { SubjectWriter } from "../contract.ts";

/**
 * The subject writer: `subject-records` alone takes this entry (the manifest's `takenBy`), passing it
 * in every change it makes. One frozen value of this module, matched by its identity, never by a
 * name: a copy of it is another value, and refused.
 */
export const subjectWriter = Object.freeze({}) as SubjectWriter;
