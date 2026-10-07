/**
 * The one reading of "frozen all the way down" the slots' suites
 * hold a value to. Internal to the kit: not exported from its entry.
 */
/**
 * The path of the first object or array in `value` that is not frozen —
 * `value` itself included — or `undefined` when every one is. A settings
 * slot is read by several modules, and one of them changing it would change
 * what the others read.
 */
export declare function unfrozenPath(value: unknown, path?: string): string | undefined;
//# sourceMappingURL=unfrozenPath.d.mts.map