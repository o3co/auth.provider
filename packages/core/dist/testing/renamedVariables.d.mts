import type { CoreRelocations } from "../config/core-relocations.mjs";
import type { Module } from "../modules/manifest/module-spec.mjs";
export interface RenamedVariableCheck {
    /**
     * The modules whose `section.renamedVariables` are held, each on its own:
     * ones installed in place of one another may each declare an old name.
     */
    readonly modules: readonly Module[];
    /** Core's own section's declaration, held beside theirs, as module "core". */
    readonly core?: CoreRelocations;
    /** The layers the names are held against, as file paths. */
    readonly layers: readonly string[];
    /**
     * Resolves a layer to plain data under `env` — for `@o3co/ts.hocon`,
     * `(path, env) => parseFile(path, { env: { ...env } }).toObject()`.
     */
    readonly read: (path: string, env: Readonly<Record<string, string>>) => unknown;
}
/**
 * What is wrong with the bindings of the renames `check.modules` (and
 * `check.core`) declare across `check.layers`, one line per problem, sorted:
 * a declaring module with no `section.reference`; a name its reference does
 * not capture as `null` unset and as its value set; a layer capturing a name
 * no module whose reference it is declares; a new name bound at its path in
 * no layer; an old name a layer binds anywhere but its capture. `[]` when
 * nothing is.
 */
export declare function renamedVariableProblems(check: RenamedVariableCheck): string[];
export interface RenamedVariableCaptureInput {
    /** The modules whose `section.renamedVariables` are captured. */
    readonly modules: readonly Module[];
    /** Core's own section's declaration, captured beside theirs. */
    readonly core?: CoreRelocations;
    /** The environment the configuration is substituted with. */
    readonly env: Readonly<Record<string, string | undefined>>;
}
/**
 * What a resolution under `env` captures in `renamed-variables` for the
 * renames `input.modules` (and `input.core`) declare: each old and new name's
 * value, `null` when unset. For a configuration built by hand, which must
 * capture every declared name from the environment it is substituted with.
 */
export declare function renamedVariableCaptures(input: RenamedVariableCaptureInput): Record<string, string | null>;
//# sourceMappingURL=renamedVariables.d.mts.map