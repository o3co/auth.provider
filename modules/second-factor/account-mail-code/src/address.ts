import { canonicalAddress } from "@mod/mail";

/** The address to compare and send to: NFC, then mail's canonical form (its domain in ASCII, lower case); none when mail takes no such address. */
export const addressOf = (value: string): string | undefined =>
	canonicalAddress(value.normalize("NFC"));

/** What a page shows of an address: its first character, then the domain. */
export function masked(address: string): string {
	const at = address.lastIndexOf("@");
	// mail's isAddress takes no quoted local part, so the first character is the address's, by code point.
	const [first] = address;
	return `${first}***@${address.slice(at + 1)}`;
}
