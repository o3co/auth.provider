import { type Module } from "@o3co/auth-provider-core";
/**
 * KeyStore module — provides the JWT signing KeyStore from config.
 *
 * Per A2-γ §4 worked example. Composition-root-local: the standalone template
 * uses the built-in local/jwks adapters; alternative deployments wire their
 * own KeyStore via a different module of the same shape.
 */
export declare const keyStoreModule: Module;
/**
 * Repositories module — provides client / user / code repositories from
 * `config.repositories.*` slices using the built-in adapter factories.
 */
export declare const repositoriesModule: Module;
/**
 * Stores module — provides the four-store user-session split + federation
 * token store. The standalone template uses in-memory stores by default; a
 * redis-backed deployment swaps this module for `@o3co/auth-provider-redis`'s
 * equivalent (per A4 §10 / Phase 5).
 */
export declare const storesModule: Module;
/**
 * Google federation config bridge — supplies the typed `googleFederationConfig`
 * ComponentMap slot from the `config.federations.google` slice.
 *
 * Per `@o3co/auth-provider-federation-google` README. Per-federation modules
 * (Phase 7 A5) consume this slot; the bridge is the standalone composition
 * root's responsibility because the slot's content is consumer-specific.
 */
export declare const googleFederationConfigModule: Module;
//# sourceMappingURL=modules.d.mts.map