import type { Module } from "../modules/manifest/module-spec.mjs";
export interface SectionStrictnessOptions {
    /**
     * The configuration a sample of each section is read from, at the
     * section's path: a resolved configuration, or a package's
     * `reference.conf`, as plain data.
     */
    readonly tree?: unknown;
    /**
     * More samples per module name, checked beside what `tree` holds for its
     * section: the levels and the forms `tree` does not reach. A module with
     * neither is sampled as `{}`.
     */
    readonly samples?: Readonly<Record<string, readonly unknown[]>>;
    /**
     * The levels whose keys are open by design, each an operator path
     * (`<section>.<path>`, `*` matching any one key) mapped to why. An
     * exemption inside a checked section that matches no level keeping an
     * unknown key is itself a problem, so the list only shrinks.
     */
    readonly exempt?: Readonly<Record<string, string>>;
}
/**
 * Every object level of the modules' sections where an unknown key is not
 * refused, as `<section>.<path>: …`, one line per problem, sorted — `[]` when
 * nothing is. Also named: a level the schema declares that no sample reaches
 * (`<section>.<path>`, `*` for any record key or list index), a sample its
 * schema refuses (or cannot parse synchronously), an exemption with no
 * reason, and an exemption inside a checked section that matches no level
 * keeping an unknown key. A module without a section is skipped; an
 * exemption outside every checked section is left to the check that holds
 * its module.
 */
export declare function sectionStrictnessProblems(modules: readonly Module[], options?: SectionStrictnessOptions): string[];
//# sourceMappingURL=sectionStrictness.d.mts.map