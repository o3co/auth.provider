/**
 * Built-in module that provides the in-process memory {@link ConsentStore}
 * (#527) and, with it, the memory {@link PendingConsentStore} the consent
 * step parks requests in (#552): one feature, one switch, so the two cannot
 * be wired apart. Dev and single-replica only — no persistence across
 * restarts, and refused by name under `deployment.mode = "multi"`.
 */
export declare const memoryConsentStoreModule: import("../modules/index.mjs").Module;
//# sourceMappingURL=module.d.mts.map