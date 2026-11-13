import { expect, it } from "vitest";
import { canonicalAddress, isAddress } from "../src/contract.ts";

it("holds a local part to 64 bytes, and a domain's ASCII form to 63 octets a label and 253 in all", () => {
	expect(isAddress(`${"\u00fc".repeat(32)}@example.test`)).toBe(true);
	expect(isAddress(`${"\u00fc".repeat(32)}a@example.test`)).toBe(false);
	expect(isAddress(`a@${"b".repeat(63)}.test`)).toBe(true);
	expect(isAddress(`a@${"b".repeat(64)}.test`)).toBe(false);
	// A label beyond ASCII is longer in its ASCII form: 55 letters and one more make 63 octets there.
	const label = (n: number) => `${"a".repeat(n)}\u00fc`;
	expect(isAddress(`a@${label(55)}.test`)).toBe(true);
	expect(isAddress(`a@${label(56)}.test`)).toBe(false);
	// Labels of 63 octets each: 63 * 3 + 3 + 61 = 253 in ASCII form, one more past it.
	const three = [label(55), label(55), label(55)];
	expect(isAddress(`a@${[...three, "f".repeat(61)].join(".")}`)).toBe(true);
	const past = `a@${[...three, "f".repeat(62)].join(".")}`;
	expect(Buffer.byteLength(past)).toBeLessThan(254);
	expect(isAddress(past)).toBe(false);
});

it("takes one address, ASCII or not, and refuses what is not one: a path, a display name, a list, no text, an xn-- label that does not hold", () => {
	expect(["a@example.test", "a@\u4f8b\u3048.jp"].map(isAddress)).toEqual([true, true]);
	const refused = [
		"a@victim.test/x",
		"Name <a@example.test>",
		"a@example.test, b@example.test",
		7,
		"a@xn--a.example",
	];
	expect(refused.map(isAddress)).toEqual([false, false, false, false, false]);
});

it("puts an address in one form: its domain in IDNA's ASCII form, lowercase, its local part as given", () => {
	expect(canonicalAddress("Ann.B@Example.TEST")).toBe("Ann.B@example.test");
	expect(canonicalAddress("a@\u4f8b\u3048.JP")).toBe("a@xn--r8jz45g.jp");
	expect(canonicalAddress("a@xn--r8jz45g.jp")).toBe(canonicalAddress("a@\u4f8b\u3048.jp"));
	for (const refused of ["a@victim.test/x", "Name <a@example.test>", "no-at-sign"]) {
		expect(canonicalAddress(refused), refused).toBeUndefined();
	}
});
