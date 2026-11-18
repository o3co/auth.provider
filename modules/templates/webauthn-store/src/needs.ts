/**
 * The needs a feature states as `true`, each met by what a space declares; a need of another value,
 * such as a bound, is no guarantee, and is read where the space states it.
 */
export type StatedNeeds<N> = { readonly [K in keyof N]: N[K] extends true ? K : never }[keyof N];
