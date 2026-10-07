/**
 * boot/config-slot.mts: who may read the `config` slot, the whole
 * configuration — core's own modules, known by identity — and the stage-1
 * refusal of every other module that lists it. The check guards what a module
 * declares: deployment code runs in-process and is trusted, so code that
 * rewrites one of core's own module objects keeps that object's identity, and
 * is outside what this check guards.
 */
import type { Module } from "../modules/manifest/module-spec.mjs";
import { type NormalisedModule } from "./types.mjs";
/**
 * Core's modules that read the whole configuration: the manifest objects core
 * ships, held by identity, never by name, so a module of another package
 * named as one of them, or a copy of one, is not one. A module of core's that
 * comes to read `config` is added here; the list shrinks as they move to
 * their own sections and slots.
 */
export declare const CONFIG_READING_CORE_MODULES: readonly Module[];
/**
 * A module that is not one of {@link CONFIG_READING_CORE_MODULES} and lists
 * `config` in its `requires` or its `optional` refuses boot
 * (`reserved-component-key`), naming the module and the slot: a module reads
 * its own section, as `deps.section`, and what another module owns through a
 * slot. `rawModules` are the manifests as the composition listed them, which
 * carry their identity; `modules` their normalised lists, index for index.
 * @internal
 */
export declare function checkConfigSlotCoreOnly(rawModules: readonly Module[], modules: readonly NormalisedModule[]): void;
//# sourceMappingURL=config-slot.d.mts.map