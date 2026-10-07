/** The host maps boot reads, by the name a refusal gives them. */
export type HostMapName = "bootstrapComponents" | "overrideComponents" | "contributionKinds";
/**
 * `map` as boot reads it (see this file's header): its own string keys listed
 * once, each slot's own property read once — an own enumerable one, and
 * `bootstrapComponents.config` and `configDefaults` whether or not
 * enumerable — into a map without a prototype;
 * `bootstrapComponents.config` copied as frozen plain data. An own
 * `__proto__` is kept as a key holding `undefined`, its value never read:
 * stage 1 refuses it whatever it holds. A map this function answered is
 * answered as it is.
 */
export declare function snapshotHostMap<T>(map: T, name: HostMapName): T;
//# sourceMappingURL=host-maps.d.mts.map