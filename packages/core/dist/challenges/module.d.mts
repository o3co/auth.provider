/**
 * Built-in module that provides the in-process memory ChallengeStore.
 * Per A1 §8.1.
 */
export declare const memoryChallengeStoreModule: import("../modules/manifest/module-spec.mjs").Module;
/**
 * Built-in module that provides the default 3-outcome ChallengeCeremony
 * composed from challengeStore + replaySeenSet.
 *
 * Per A1 §8.1. Override path: replace this module with a custom one that
 * provides challengeCeremony from different deps; the boot planner enforces
 * provides uniqueness (BootError reason "duplicate-provides" if both are
 * added).
 */
export declare const defaultChallengeCeremonyModule: import("../modules/manifest/module-spec.mjs").Module;
//# sourceMappingURL=module.d.mts.map