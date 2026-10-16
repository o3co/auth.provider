/** Twenty consonants: no vowels to spell words, no digits to mistake for letters. */
const alphabet = "BCDFGHJKLMNPQRSTVWXZ";
const length = 8;

const hyphenated = (code: string) => `${code.slice(0, 4)}-${code.slice(4)}`;

/** Letters from fresh bytes, without end; a byte that would favor some letters is passed over. */
function* fairLetters(bytes: (n: number) => Uint8Array): Generator<string, never> {
	for (;;) {
		for (const byte of bytes(length * 2)) {
			// 240 is the largest multiple of 20 below 256: the rest would favor the first letters.
			if (byte < 240) yield alphabet.charAt(byte % alphabet.length);
		}
	}
}

/** A user code drawn without bias, as `XXXX-XXXX`. */
export function userCodeFrom(bytes: (n: number) => Uint8Array): string {
	const letters = fairLetters(bytes);
	return hyphenated(Array.from({ length }, () => letters.next().value).join(""));
}

/** The code a user typed, with case, spaces and hyphens forgiven; nothing for any other character. */
export function normalized(typed: string): string | undefined {
	// Checked before upper-casing, which turns some characters outside ASCII into letters.
	if (!/^[A-Za-z\s-]*$/.test(typed)) return undefined;
	const code = typed.toUpperCase().replace(/[\s-]/g, "");
	if (code.length !== length || [...code].some((c) => !alphabet.includes(c))) return undefined;
	return hyphenated(code);
}
