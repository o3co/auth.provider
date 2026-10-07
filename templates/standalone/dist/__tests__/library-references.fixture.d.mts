import { type AppConfig } from "@o3co/auth-provider-core";
import { type Config } from "@o3co/ts.hocon";
import { type Switches } from "../configPath.mjs";
import { type Adapters } from "../sections.mjs";
/** The libraries' references resolved under `env`, in the order `app.mts` layers them. */
export declare function libraryLayers(env: Readonly<Record<string, string>>): Config;
/** Phase one's switches laid over the configuration boot parses. */
export type BothPhases = Switches & AppConfig;
/**
 * `switches` laid over `resolved`, the configuration boot parses, as a test
 * that hands one object to both phases does: the composition root's own keys
 * beside the sections, and `federation-grants.enabled` written as phase one
 * decided it into the section as resolved. Boot is so handed phase one's
 * boolean, not the value as written, unlike `app.mts`; boot's refusal of a
 * written value phase one installs the modules for is pinned in
 * `two-phase-config.test.mts`.
 */
export declare function withSwitches(resolved: Readonly<Record<string, unknown>>, switches: Switches): BothPhases;
/**
 * A resolution — `layers`, the template's `config/reference.conf` among them,
 * under `env` — as a test that resolves by hand hands it to both phases at
 * once: the configuration as resolved and unparsed, which boot parses as
 * `app.mts` hands it on, with what phase one reads of it (`readSwitches`)
 * laid over it — the composition root's `adapters` and `mfaMode`, the Store
 * transport settings, and `federation-grants.enabled` as phase one decides
 * it.
 */
export declare function bothPhasesOf(layers: Config, env: Readonly<Record<string, string>>): BothPhases;
/**
 * The composition root's `adapters` a resolution holds — `layers`, the
 * template's `config/reference.conf` among them, under `env` — as phase one
 * reads them.
 */
export declare function adaptersOf(layers: Config, env: Readonly<Record<string, string>>): Adapters;
/** The adapters the template ships, as its `config/reference.conf` sets them with no environment. */
export declare function shippedAdapters(): Adapters;
/** The shipped adapters with every store the template can hold in process there: no Redis connection needed. */
export declare function inProcessAdapters(): Adapters;
/**
 * The `renamed-variables` section a resolution under `env` holds: what every
 * module above captures, and the Redis code repository's, which the
 * in-process one's excludes from one composition (both declare
 * CLIENT_CODE_DEFAULT_EXPIRES_IN renamed, each to its own new name).
 */
export declare function capturedRenames(env: Readonly<Record<string, string | undefined>>): Record<string, string | null>;
//# sourceMappingURL=library-references.fixture.d.mts.map