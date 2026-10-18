import { domainToASCII, domainToUnicode } from "node:url";

// No space, control or format character, and no route operator (`%`, `!`).
const part = String.raw`[^\s\p{Cc}\p{Cf}@,;:<>()[\]"\\%!]+`;
const address = new RegExp(`^${part}@${part}$`, "u");
/** An encoded word (RFC 2047), which a mail reader decodes into other text. */
const encodedWord = /=\?.*\?=/;

/** Letters, digits and hyphens, in labels between dots. */
const ldh = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/;

/** An `xn--` label decodes to other letters and encodes back to itself; some Node versions pass one that does not. */
function aLabelHolds(label: string): boolean {
	if (!label.startsWith("xn--")) return true;
	const unicode = domainToUnicode(label);
	return unicode !== label && domainToASCII(unicode) === label;
}

/**
 * A domain read one way: its IDNA ASCII form is LDH of at most 253 octets, 63 a label, every A-label
 * holding, and it is that form or its Unicode form, case aside. IDNA drops what follows `/`, `?` or
 * `#` and maps full-width letters, so sending the ASCII form would otherwise reach another domain.
 */
function readsAsItself(domain: string): boolean {
	const ascii = domainToASCII(domain);
	const own = domain.toLowerCase();
	if (ascii.length > 253 || !ldh.test(ascii)) return false;
	if (!ascii.split(".").every((label) => label.length <= 63 && aLabelHolds(label))) return false;
	return own === ascii || own === domainToUnicode(ascii);
}

/**
 * Whether `to` is one address mail takes: at most 254 bytes in UTF-8 and a local part of at most 64
 * (RFC 5321), letters beyond ASCII allowed. A sender checks its own configured addresses by it too.
 */
export function isAddress(to: unknown): to is string {
	if (typeof to !== "string" || !to.isWellFormed()) return false;
	if (Buffer.byteLength(to) > 254 || !address.test(to) || encodedWord.test(to)) return false;
	const at = to.indexOf("@");
	return Buffer.byteLength(to.slice(0, at)) <= 64 && readsAsItself(to.slice(at + 1));
}

/** One form for comparing addresses: the domain in IDNA's ASCII form, lowercase, the local part as given; none for a string that is no address. */
export function canonicalAddress(to: string): string | undefined {
	if (!isAddress(to)) return undefined;
	const at = to.lastIndexOf("@");
	return `${to.slice(0, at)}@${domainToASCII(to.slice(at + 1))}`;
}
