import type { FederationSettings } from "../federations/settings.mjs";
/**
 * Every `core.federations` entry of `config`, by name in the map's order,
 * as `ConfiguredFederation`: its type, whether it is on, whether its
 * upstream `amr` counts, whether its callback alone meets a freshness ask, and `callbackURL`, `issuer` and `clientId` where
 * written as non-empty strings — nothing else of it, so no secret. The map
 * inherits nothing and is frozen with each entry. Reads the configuration
 * core's schema parsed, which holds every entry to an object naming its type
 * and coerces its switches.
 * @internal
 */
export declare function federationSettingsOf(config: unknown): FederationSettings;
//# sourceMappingURL=federation-settings.d.mts.map