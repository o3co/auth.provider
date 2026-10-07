import { type CoreConfig } from "./application.schema.mjs";
/** Core's own section, `core {}`, as its schema parses it. */
export type CoreSection = NonNullable<CoreConfig["core"]>;
/**
 * `core {}` of `raw`, parsed by the schema boot parses it with: strict at
 * every level but a federation's entry, whose keys beyond core's own pass
 * through for its type's schema to parse at boot; a variable's string
 * coerced as boot coerces it. An absent
 * section is an empty one. No other section is parsed or refused here; each
 * is its module's to read.
 *
 * @throws RangeError naming each refused path (`core.…`, or the
 *   configuration itself when it is not an object) — an unknown key by its
 *   name, never its value — with the schema's error as its `cause`; a read
 *   that throws is refused the same way, carrying what it threw.
 */
export declare function readCoreSection(raw: unknown): CoreSection;
//# sourceMappingURL=core-section.d.mts.map