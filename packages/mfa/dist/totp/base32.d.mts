/** `bytes` in RFC 4648 base32, upper case, without padding. */
export declare function encodeBase32(bytes: Uint8Array): string;
/** The bytes `text` encodes, or `undefined` when it is not what {@link encodeBase32} would write. */
export declare function decodeBase32(text: string): Buffer | undefined;
//# sourceMappingURL=base32.d.mts.map