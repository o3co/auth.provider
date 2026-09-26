import { type AppConfig, type Module } from "@o3co/auth-provider-core";
/**
 * Test-only overrides allowing the smoke test to substitute in-memory
 * implementations of the file-system-backed modules. Production callers
 * should not pass overrides; the defaults match the standalone scaffold.
 */
export interface BuildModulesOverrides {
    readonly keyStoreModule?: Module;
    readonly repositoriesModule?: Module;
    readonly storesModule?: Module;
}
/**
 * Compose the standalone v0.5.0 module list from `config`. Splitting this
 * out of `app.mts` keeps the composition root testable: a smoke test can
 * verify that disabling a federation removes its module pair from the
 * manifest without spinning up a full HTTP server.
 *
 * Federation gating: `googleFederationModule` requires `googleFederationConfig`,
 * which `googleFederationConfigModule` produces by reading
 * `config.federations.google`. When google is disabled (or the section is
 * absent), the config-bridge module's provider throws — so the entire pair
 * MUST be conditionally included at composition time, not gated inside the
 * provider.
 */
export declare function buildModules(config: AppConfig, overrides?: BuildModulesOverrides): Module[];
//# sourceMappingURL=buildModules.d.mts.map