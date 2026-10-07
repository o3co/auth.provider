/**
 * Canonical (scope, value) → string encoding shared by every ChallengeStore /
 * ReplaySeenSet adapter. The length-prefix form prevents delimiter-collision
 * between e.g. ("ab", "cd") and ("abcd", "") so different (scope, value) pairs
 * NEVER share an internal key.
 *
 * Length unit is JS String.prototype.length (UTF-16 code units). The absolute
 * value is irrelevant; what matters is that all adapters compute identically.
 *
 * Per A1 §7.3.
 */
export declare function canonicalKey(scope: string, value: string): string;
//# sourceMappingURL=canonical-key.d.mts.map