import type { AppConfig } from "../config/application.schema.mjs";
import type { ComponentMap } from "../modules/manifest/component-map.mjs";
import type { Module } from "../modules/manifest/module-spec.mjs";
import type { BootstrapMap, ContributionKindMap, ValidatedManifests } from "./types.mjs";
/**
 * Input shape accepted by `validateManifests`. Mirrors `CreateAppOptions`
 * minus the generic `B` parameter (the bootstrap map is typed at the
 * `createApp` call site; stage 1 receives it erased to `BootstrapMap`).
 *
 * Per A2-β §5.1.
 */
export interface ValidateManifestsInput {
    readonly modules: readonly Module[];
    readonly bootstrapComponents: BootstrapMap;
    readonly contributionKinds?: ContributionKindMap;
    readonly overrideComponents?: Partial<ComponentMap>;
}
/**
 * If `mfaCoordinator` is provided by any module, both `mfaProviderFactory`
 * and `mfaTransactionStore` MUST also be provided. Otherwise the first MFA
 * flow crashes at runtime with a confusing `Cannot read properties of
 * undefined`.
 *
 * Per issue #101, A2-β amendment 2026-05.
 */
export declare function checkMfaPartialWiring(plannedKeys: ReadonlySet<string>): void;
/**
 * If any `config.federations.<name>.enabled === true`, all 6 session/
 * federation/refresh-token-family slots MUST be present in the planned
 * component set. A missing store causes federation routes either to 503 at
 * runtime with an opaque error (session/federationToken stores) or to never
 * mount at all (refreshTokenFamilyRevocation — see packages/oauth/src/routes.mts
 * `logoutSupported` / `federationTokenSupported` gates), surfacing as
 * unexpected 404s. Both failure modes are equally opaque from the operator's
 * perspective; the validator surfaces them at boot time.
 *
 * Per issue #101 TODO-F-1, A2-β §6.1 amendment 2026-05; refreshTokenFamilyRevocation
 * gating added per #103 review (alignment with route-level gating in oauth/routes.mts).
 */
export declare function checkFederationStoresWiring(config: AppConfig, plannedKeys: ReadonlySet<string>): void;
/**
 * Stage 1 of the A2-β boot planner pipeline. Accepts the consumer's
 * `Module[]`, `bootstrapComponents`, `contributionKinds`, and
 * `overrideComponents` and runs 14 ordered sub-checks.
 *
 * Returns a `ValidatedManifests` on success. Throws a typed `BootError`
 * on the first violation in input-array order.
 *
 * The stage is **deterministic and side-effect-free**: same inputs → same
 * output / same error. Per A2-β §5.1.
 */
export declare function validateManifests(input: ValidateManifestsInput): ValidatedManifests;
//# sourceMappingURL=validate-manifests.d.mts.map