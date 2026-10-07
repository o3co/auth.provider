import type { SubjectSessionIndex } from "../types.mjs";
/**
 * In-memory {@link SubjectSessionIndex} (#296).
 *
 * Deliberately **not** built on `createMemorySidSortedSet`, despite the shape
 * looking identical. That primitive keeps one expiry per *key*, which is
 * correct for the sid-keyed indexes — every member there belongs to the one
 * session and shares its expiry, and its own comment says so: "same-sid writes
 * always carry the SAME expiresAt".
 *
 * A subject-keyed index breaks that assumption. One subject's sessions expire
 * at different times, so a single bucket expiry would either keep an expired
 * session listed (when a later session extends the bucket) or drop a live one
 * early (when an earlier-expiring session shortens it). Neither is acceptable
 * for the index a credential change enumerates. Expiry is therefore tracked
 * per member.
 *
 * GC is lazy — expired members are dropped when the subject is read — with no
 * background sweep, matching the other in-memory stores here.
 */
export declare function createInMemorySubjectSessionIndex(): SubjectSessionIndex;
//# sourceMappingURL=subjectSessionIndex.d.mts.map