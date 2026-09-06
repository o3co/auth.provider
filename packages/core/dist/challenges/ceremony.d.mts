import type { ReplaySeenSet } from "../replay-seen-set/types.mjs";
import type { ChallengeCeremony, ChallengeStore } from "./types.mjs";
/**
 * Inputs for the 3-outcome challenge ceremony composition.
 * Per A1 §6 (lines 341-398).
 */
export interface ChallengeCeremonyDeps {
    readonly challengeStore: ChallengeStore;
    readonly replaySeenSet: ReplaySeenSet;
}
/**
 * ChallengeCeremony composition: combines ChallengeStore (issue/find/
 * consume) and ReplaySeenSet (markSeen/contains) into the 3-outcome wrapper
 * (consumed | replayed | unknown).
 *
 * Three-branch control flow:
 *   1. find → null     → contains → outcome `replayed | unknown`
 *   2. find → Challenge, consume → true  → markSeen (swallow expired-at-issue) → outcome `consumed`
 *   3. find → Challenge, consume → false → outcome `replayed` (race-loss / TTL boundary, fail-closed)
 *
 * Acknowledged consume→markSeen propagation gap (§6.1): sub-millisecond on
 * single Redis instance, ~1ms under realistic jitter. Bounded fraction of
 * sane challenge TTL. Security impact zero (both `unknown` and `replayed`
 * cause caller to reject). Audit signal impact bounded.
 *
 * Per A1 §6 + §6.1.
 */
export declare function createChallengeCeremony(deps: ChallengeCeremonyDeps): ChallengeCeremony;
//# sourceMappingURL=ceremony.d.mts.map