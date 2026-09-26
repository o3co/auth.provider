/**
 * What a contribution factory may answer with: the value, or a promise of it.
 *
 * `applyContributions` awaits every kind, so a factory that needs I/O to build
 * what it contributes — an adapter discovering its issuer's metadata at boot,
 * a mechanism reading a key — is legitimately `async`. The contract says what
 * boot accepts, and every kind boot awaits says it (#626 P1).
 *
 * It does not widen what a consumer reads: the collector holds the awaited
 * value, so `federationProviders` is still a map of `FederationProvider`.
 *
 * Its own module because `contributes-map` and `route-contribution` both name
 * it and the first already imports the second.
 */
export type Contributed<T> = T | Promise<T>;
//# sourceMappingURL=contributed.d.mts.map