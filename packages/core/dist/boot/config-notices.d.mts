import type { Logger } from "../logging/Logger.mjs";
/** What the notices are read from. */
export interface ConfigNoticeInput {
    /** The configuration as handed to boot, captures of renamed variables included. */
    readonly config: unknown;
    /** The top-level sections something loaded owns: core, or a loaded module. */
    readonly owned: ReadonlySet<string>;
    /**
     * The configuration's defaults as `readConfigDefaults` copied them;
     * `undefined` when the composition handed none.
     */
    readonly defaults: ConfigDefaults | undefined;
    /** The variable names a loaded module, or core, declares renamed: old and new. */
    readonly judged: ReadonlySet<string>;
}
/** The configuration's defaults, as `readConfigDefaults` copied them: plain data, keyed by section. */
export type ConfigDefaults = Readonly<Record<string, unknown>>;
/** Why `configDefaults` cannot be read as plain data, and where: the keys from its top, `[]` for itself. */
export interface ConfigDefaultsProblem {
    readonly path: readonly string[];
    readonly problem: string;
}
/**
 * `bootstrapComponents.configDefaults`, read once into a copy of its plain
 * data — `undefined` when handed none, or handed `undefined` — or why it is
 * not plain data: an object of sections whose every value is a string, a
 * number, a boolean, `null`, a list or an object (prototype `Object.prototype`
 * or none), each an own data property. An accessor is refused whether or not
 * it throws, and so is a throw as it is read, a Proxy's included. The copy
 * keeps each object's prototype, which the notices' comparison reads.
 */
export declare function readConfigDefaults(value: unknown): {
    readonly defaults: ConfigDefaults | undefined;
} | ConfigDefaultsProblem;
/**
 * Logs each notice that names something, once, at warn, to `logger`:
 * `config_sections_ignored` and `config_sections_not_loaded` with
 * `{ sections }`, `environment_variables_not_applied` with `{ variables }`.
 * Without a logger, nothing is heard.
 */
export declare function logConfigNotices(logger: Logger | undefined, input: ConfigNoticeInput): void;
//# sourceMappingURL=config-notices.d.mts.map