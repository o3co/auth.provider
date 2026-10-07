/**
 * The template's refusals before boot, as core's `BootError`: each under the
 * reason boot raises for the same case, at the stage boot raises it in
 * (`validateManifests`), so that an alert keyed on a boot error's reason sees
 * every refusal to start. The template's checks stay its own; only how a
 * refusal is reported is boot's.
 *
 * The details name a module as boot does. A key of the composition root's
 * own — the `adapters` section, the `mfaMode` switch — is named after itself,
 * as boot names core's own section "core": a module with a section under
 * either name is refused (`resolveForBoot`), so the name points at the key.
 */
import { BootError, type ConfigPathRelocatedDetails, type ConfigValidationFailedDetails, type EnvironmentVariableRenamedDetails } from "@o3co/auth-provider-core";
/** A Zod issue as `config-validation-failed` carries one: its path is the path in the configuration. */
export type ConfigIssue = ConfigValidationFailedDetails["issues"][number];
/** An issue at `path` of the configuration that no schema raised: what is wrong there, in `message`. */
export declare function customIssue(path: readonly string[], message: string): ConfigIssue;
/** `issues`, each with `prefix`, the path its schema read at, in front of its own path. */
export declare function issuesAt(prefix: readonly string[], issues: readonly ConfigIssue[]): ConfigIssue[];
/**
 * `config-validation-failed`: `issues` at their paths, refused in the
 * sections `modules` read, each at its `schemaPath`.
 */
export declare function configRefused(message: string, issues: readonly ConfigIssue[], modules: ConfigValidationFailedDetails["modules"]): BootError;
/**
 * `config-validation-failed` for one key, at `path`, of the section `module`
 * reads at its own name: `message` is the refusal and the issue's message.
 */
export declare function keyRefused(message: string, module: string, path: readonly string[]): BootError;
/** `config-path-relocated`: each key still set at a path it moved from. */
export declare function pathsRelocated(message: string, relocated: ConfigPathRelocatedDetails["relocated"]): BootError;
/** `environment-variable-renamed`: each old variable name set, with no value. */
export declare function variablesRenamed(message: string, renamed: EnvironmentVariableRenamedDetails["renamed"]): BootError;
/** `module-section-path-invalid`: `module`'s section is read at `at`, which `problem` says it may not be. */
export declare function sectionPathRefused(message: string, module: string, at: string, problem: string): BootError;
//# sourceMappingURL=bootRefusal.d.mts.map