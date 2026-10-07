/**
 * The test double of the `federationSettings` slot:
 * `createTestFederationSettings` builds the map core fills the slot with from
 * the entries a test names; it checks nothing.
 */
import type { ConfiguredFederation, FederationSettings } from "../../federations/settings.mjs";
/** One entry as a test names it: its type, and whatever else it sets. */
export type TestFederationEntry = Pick<ConfiguredFederation, "type"> & Partial<Omit<ConfiguredFederation, "type">>;
/**
 * The settings for the entries a test names, in its order, frozen and
 * inheriting nothing; `{}` when it names none. An entry is enabled unless it
 * says otherwise, its upstream `amr` does not count unless it says so, its
 * callback meets a freshness ask as core's default says unless it says
 * otherwise, and an
 * enabled one without a `callbackURL` gets
 * `https://auth.test/session/oauth/federation/<name>/callback`; `issuer` and
 * `clientId` only when given. Only the members of `ConfiguredFederation` are
 * kept.
 */
export declare function createTestFederationSettings(entries?: Readonly<Record<string, TestFederationEntry>>): FederationSettings;
//# sourceMappingURL=federationSettings.d.mts.map