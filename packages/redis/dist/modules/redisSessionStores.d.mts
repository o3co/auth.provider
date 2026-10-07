/**
 * Bundled module providing all 4 redis-backed user-session stores against
 * the per-purpose ComponentMap slots `userSessionStoreClient`,
 * `sessionRPRegistryClient`, `sessionFamilyIndexClient`, and
 * `sessionFederationIndexClient` (declared in `@o3co/auth-provider-core`'s
 * `user-sessions/types.mts`). Per A4 §8.1 + §10.1.
 *
 * `keyPrefix` is the OUTER namespace; the bundled module appends fixed
 * subprefixes per store (`us:` / `rp:` / `fi:` / `fed:`). Consumers that
 * need to override individual subprefixes use the per-adapter constructors
 * with custom keyPrefix values; bundled module enforces a consistent scheme.
 *
 * Recurring issue class 2: `requires` includes `"config"` because
 * `deps.config` is read in `provides`.
 */
export declare const redisSessionStoresModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=redisSessionStores.d.mts.map