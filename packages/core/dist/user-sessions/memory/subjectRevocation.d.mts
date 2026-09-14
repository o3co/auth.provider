import type { SubjectRevocation } from "../types.mjs";
/**
 * In-process Map-backed {@link SubjectRevocation} (#296).
 *
 * GC is lazy — expired watermarks are dropped when read — mirroring
 * `createMemoryAccessTokenDenylist`. No background sweep.
 *
 * A second `revokeBefore` for the same subject takes the **later** watermark
 * rather than the newer call's value. Two credential changes in quick
 * succession must not have the second one, computed on a replica whose clock
 * is behind, move the line backwards and resurrect tokens the first one killed.
 */
export declare function createInMemorySubjectRevocation(): SubjectRevocation;
//# sourceMappingURL=subjectRevocation.d.mts.map