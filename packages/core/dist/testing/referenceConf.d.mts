import type { Module } from "../modules/manifest/module-spec.mjs";
export interface ReferenceConfCheck {
    /** The package's `config/reference.conf`, resolved to plain data. */
    readonly tree: unknown;
    /** The file's URL, as its modules declare it in `section.reference`. */
    readonly reference: URL;
    /** The package's modules; those declaring `reference` are the file's owners. */
    readonly modules: readonly Module[];
}
/**
 * What is wrong with a package's `reference.conf`, one line per problem,
 * sorted (`[]` when nothing is): no module declares `reference`; a path
 * outside every declaring module's section; a section its schema refuses,
 * each issue at its operator path; a path its schema's output lacks.
 */
export declare function referenceConfProblems(check: ReferenceConfCheck): string[];
export interface PackageReferenceCheck {
    /** The package's `config/reference.conf`, as its modules declare it. */
    readonly reference: URL;
    /** The modules that read the file: each must declare it as its section's reference. */
    readonly modules: readonly Module[];
    /**
     * Resolves the file at a path to plain data with the package's HOCON
     * reader, under `env` — for `@o3co/ts.hocon`,
     * `(path, env) => parseFile(path, { env: { ...env } }).toObject()`.
     */
    readonly read: (path: string, env: Readonly<Record<string, string>>) => unknown;
}
/**
 * The check a package's own test runs over its `config/reference.conf`, one
 * line per problem, sorted — `[]` when nothing is: every module in `modules`
 * declares the file as its section's reference,
 * {@link referenceConfProblems} finds nothing wrong with the file as `read`
 * resolves it with no variable set, and `renamedVariableProblems` nothing
 * wrong with the bindings of the renames the modules declare. Core's tests
 * require every package that ships a reference to run it.
 */
export declare function packageReferenceProblems(check: PackageReferenceCheck): string[];
//# sourceMappingURL=referenceConf.d.mts.map