/**
 * In-memory FederationTokenStore module. Maps to the existing
 * `createInMemoryFederationTokenStore` adapter (plaintext, single-process).
 *
 * For production, use `redisFederationTokenStoreModule` from
 * `@o3co/auth-provider-redis`.
 *
 * Phase 10 Q5: completes the Module-pattern parity for the
 * `federationTokenStore` ComponentMap slot (added in Phase 9 Task 4).
 */
export declare const memoryFederationTokenStoreModule: import("../modules/index.mjs").Module;
//# sourceMappingURL=module.d.mts.map