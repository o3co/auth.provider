/**
 * What core's own contract suites of the slots it fills share: the shape of
 * a case, and the one reading of "frozen all the way down" a settings slot
 * is held to. Not on the testing entry: the suites of the slots other
 * modules fill are `@o3co/auth-provider-test-kit`'s.
 */
/** One rule of a contract: its name, and a run that throws when the value under test breaks it. */
export interface ContractCase {
    readonly name: string;
    readonly run: () => Promise<void>;
}
/**
 * The path of the first object or array in `value` that is not frozen —
 * `value` itself included — or `undefined` when every one is. A settings
 * slot is read by several modules, and one of them changing it would change
 * what the others read.
 */
export declare function unfrozenPath(value: unknown, path?: string): string | undefined;
//# sourceMappingURL=shared.d.mts.map