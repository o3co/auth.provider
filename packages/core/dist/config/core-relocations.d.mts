/**
 * What core's own section, `core`, moved from and the environment variables
 * renamed with it: boot holds and applies it as it does a loaded module's
 * `section.relocatedFrom` and `section.renamedVariables`, as module "core",
 * and core's `reference.conf` captures each name it declares renamed.
 */
import type { ModuleSection } from "../modules/manifest/module-section.mjs";
/** Core's declaration: the two fields of a module's `section` that say where it moved from. */
export type CoreRelocations = Pick<ModuleSection, "relocatedFrom" | "renamedVariables">;
/**
 * Core's shipped declaration, frozen with every map and entry it holds: the
 * replica count, the expected session requirements, the token-binding
 * settings and the federations' map moved into `core`, with the variables
 * bound to them renamed. A variable binds `core.deployment.mode`, the two
 * token-binding keys and each key of a federation (named after its path,
 * `CORE_FEDERATIONS_<NAME>_<KEY>`): the rest of `deployment` and
 * `tokenBinding`, and the expected session requirements, have none. Core's
 * reference binds no federation's key, so it declares none of their
 * variables renamed; a composition that bound one declares that itself.
 */
export declare const CORE_RELOCATIONS: CoreRelocations;
//# sourceMappingURL=core-relocations.d.mts.map