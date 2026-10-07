/**
 * The `reference.conf` files a composition layers beneath its own
 * configuration: core's, and each loaded module's package's, as the
 * module declares it (`section.reference`). Core names the files and reads
 * none of them — it takes no HOCON dependency; the composition root parses
 * and layers them, with the files it writes itself on top.
 */
import type { Module } from "../modules/manifest/module-spec.mjs";
/**
 * Core's own `reference.conf`: the defaults of the sections core's schema
 * declares, and the bottom of every composition's chain. A new `URL` on
 * every call — a `URL` can be changed in place, and one shared object would
 * carry a change made through it to every later caller.
 */
export declare function coreReference(): URL;
/**
 * The `reference.conf` files `modules` declare, each once, in the order a
 * composition layers them beneath its own files: every module's
 * `section.reference` in module order, then {@link coreReference} at the
 * bottom (also when a module declares core's own). Each is a new `URL`, so
 * changing an answer changes neither the manifest nor a later answer.
 *
 * Fold them beneath the composition's own files in this order
 * (`own.withFallback(first).withFallback(second)…`, core's last), so where
 * two set the same path the earlier wins and core's loses to every
 * package's. The shipped references are disjoint (each package's tests hold
 * its reference to its own modules' sections via `packageReferenceProblems`,
 * and core's tests hold them disjoint), so the order among the packages
 * decides nothing today.
 *
 * A reference that is not a `file:` URL is a `RangeError` naming the
 * module: a composition root reads each one as a file.
 */
export declare function moduleReferences(modules: readonly Module[]): readonly URL[];
//# sourceMappingURL=references.d.mts.map