import { type Adapters } from "./sections.mjs";
/** The composition root's own section. No module may be named after it. */
export declare const ADAPTERS_SECTION = "adapters";
/**
 * `adapters` from `resolved` — the template's own layers over its
 * `config/reference.conf` — under `env`, the environment they were
 * substituted with, parsed with the template's schema. Refuses, each with a
 * `BootError` (`bootRefusal.mts`), a selection still written at the path it
 * moved from, naming its new path and variable (`config-path-relocated`);
 * then a variable renamed with one (`refuseRenamedVariables`); then a value
 * or a key the schema refuses, naming its path under `adapters`
 * (`config-validation-failed`).
 */
export declare function readAdapters(resolved: Readonly<Record<string, unknown>>, env: Readonly<Record<string, string>>): Adapters;
//# sourceMappingURL=adapters.d.mts.map