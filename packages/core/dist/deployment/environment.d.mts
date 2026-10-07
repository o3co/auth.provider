/** `name` trimmed and in lower case, or `undefined` for a value that is no name or an empty one. */
export declare function readEnvironmentName(name: unknown): string | undefined;
/** The first of `names` that reads as production or staging, or `undefined` when none does. */
export declare function productionEnvironmentIn(names: readonly unknown[]): "production" | "staging" | undefined;
/**
 * Whether `names` name a development or test environment: at least one of
 * them reads as a name, and every one that does reads as development or test.
 */
export declare function isDevelopmentEnvironment(names: readonly unknown[]): boolean;
//# sourceMappingURL=environment.d.mts.map