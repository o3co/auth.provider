/** Crockford's base32: no I, L, O or U, so a person reads it back without mistakes. */
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** The 16 characters of a long code, as longCode makes them. */
const longShape = /^[0-9A-HJKMNP-TV-Z]{16}$/;

/** 16 characters from 10 random bytes: 80 bits, for a code that lives as long as a binding. */
export function longCode(random: (n: number) => Uint8Array): string {
	const bytes = random(10);
	let bits = 0;
	let value = 0;
	let out = "";
	for (const byte of bytes) {
		value = (value << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			out += crockford[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
		// Only the low `bits` bits are read again; the shift drops the rest.
	}
	return out;
}

/** A long code as a person types it: any case, hyphens and spaces left out, O read as 0 and I or L as 1. */
export function readLongCode(typed: string): string | undefined {
	// ASCII first: a character that only changes case into a code's is not one.
	if (typed.length > 64 || !/^[A-Za-z0-9 -]*$/.test(typed)) return undefined;
	const plain = typed.toUpperCase().replace(/[ -]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
	return longShape.test(plain) ? plain : undefined;
}

/** Six digits, each as likely as any other: bytes past the last whole million are drawn again. */
export function shortCode(random: (n: number) => Uint8Array): string {
	const ceiling = 2 ** 32 - (2 ** 32 % 1_000_000);
	for (;;) {
		const n = Buffer.from(random(4)).readUInt32BE(0);
		if (n < ceiling) return String(n % 1_000_000).padStart(6, "0");
	}
}

/** A six-digit code as typed, white space around it left out (as `trim` takes it, NBSP and U+3000 included). */
export function readShortCode(typed: string): string | undefined {
	if (typed.length > 64) return undefined;
	const plain = typed.trim();
	return /^[0-9]{6}$/.test(plain) ? plain : undefined;
}
