/**
 * The one reading of the federations a configuration declares: the map in
 * core's own section, `core.federations`, keyed by each federation's name.
 * Each entry is as written (core's schema coerces its switches), and read as
 * own properties: a key an object inherits is not one anyone wrote. Also the
 * keys core owns on every entry, the rest being its type's, and the rule a
 * federation's name keeps.
 */
/**
 * The keys of an entry core owns — whether it is on, the type that handles
 * it, whether its upstream's `amr` counts, whether its callback alone meets a
 * freshness ask, and where the upstream redirects back to. They are removed
 * before an entry is handed to its type's schema.
 */
export declare const FEDERATION_ENTRY_CORE_KEYS: readonly string[];
/**
 * Why `name` cannot name a federation, or `undefined` when it can. A name is
 * the `:name` segment of the federation's routes and the prefix of the
 * identities it links, so it is one plain URL path segment.
 */
export declare function federationNameProblem(name: string): string | undefined;
/** The configuration's `core.federations` by name, own entries only; `{}` when it has none. */
export declare function federationsOf(config: unknown): Readonly<Record<string, unknown>>;
/**
 * The entries of `core.federations` switched on (`enabled` is `true`), by
 * name, in the configuration's key order — JavaScript's: a name that reads as
 * an integer comes first.
 */
export declare function enabledFederationsOf(config: unknown): readonly (readonly [string, object])[];
//# sourceMappingURL=configured.d.mts.map