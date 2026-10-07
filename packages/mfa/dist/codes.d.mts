/** A new long code: 10 bytes from `random` (the CSPRNG), as 16 Crockford base32 characters. */
export declare function generateLongCode(random?: (size: number) => Buffer): string;
/** `code`, as made, in four groups of four joined by hyphens; a `RangeError` for anything else. */
export declare function formatLongCode(code: string): string;
/** `input` read as a long code, as made; `undefined` when it is not one. */
export declare function readLongCode(input: unknown): string | undefined;
/** A new six-digit code: one draw below a million from `random` (the CSPRNG), zero-padded. */
export declare function generateSixDigitCode(random?: (max: number) => number): string;
/** `input` read as a six-digit code; `undefined` when it is not one. */
export declare function readSixDigitCode(input: unknown): string | undefined;
//# sourceMappingURL=codes.d.mts.map