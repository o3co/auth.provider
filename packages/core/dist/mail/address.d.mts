/**
 * `address` as {@link normaliseMailAddress} spells it, or `undefined` for a
 * value that is no address: not a string, not well-formed, carrying a
 * control character, a format character or whitespace, or not one addr-spec
 * — a dot-atom or a quoted local part of at most 64 octets as it is written,
 * holding nothing a relay could route on or decode ({@link localPartOf}),
 * then `@`, then a domain of labels as {@link domainOf} reads them.
 */
export declare function normaliseMailAddress(address: unknown): string | undefined;
//# sourceMappingURL=address.d.mts.map