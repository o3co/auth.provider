import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { certificateOf } from "../src/certificate.ts";

const der = (n: number, seed = 7) => Uint8Array.from({ length: n }, (_, i) => (i * seed) % 256);
const block = (bytes: Uint8Array, label = "CERTIFICATE") =>
	`-----BEGIN ${label}-----\n${Buffer.from(bytes).toString("base64").replace(/.{64}/g, "$&\n")}\n-----END ${label}-----\n`;
const encoded = (text: string) => encodeURIComponent(text);
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const envoy = { dialect: "xfcc" as const, header: "x-forwarded-client-cert" };
const read = (value: string) => {
	const found = certificateOf(new Map([["x-forwarded-client-cert", value]]), envoy);
	return found.kind === "certificate" ? found : "malformed";
};

const leaf = der(300);
const [ca, root] = [der(200, 11), der(180, 13)];
const cert = `Cert="${encoded(block(leaf))}"`;
const sum = `Hash=${hash(leaf)}`;

describe("an XFCC element", () => {
	it("gives the leaf and the chain behind it, in the order sent", () => {
		const chain = `Chain="${encoded(block(ca) + block(root))}"`;
		const value = `By=spiffe://proxy;${sum};${cert};${chain};Subject="CN=client,O=a;b=c";URI=spiffe://client;DNS=a.example;DNS=b.example`;
		expect(read(value)).toEqual({ kind: "certificate", leaf, chain: [ca, root] });
		expect(read(`${sum};${cert}`)).toEqual({ kind: "certificate", leaf, chain: [] });
		expect(read(`${sum};Cert=${encoded(block(leaf))}`)).toEqual({
			kind: "certificate",
			leaf,
			chain: [],
		});
	});

	it("reads quoted values whole, separators and escapes included, and keys in any case", () => {
		const other = der(300, 3);
		const posing = `Subject="x;Cert=${encoded(block(other))}"`;
		expect(read(`${posing};${sum};${cert}`)).toMatchObject({ leaf });
		expect(read(`Subject="a\\"b\\\\c, d";${sum};${cert}`)).toMatchObject({ leaf });
		expect(read(` hash = ${hash(leaf)} ; CERT=${encoded(block(leaf))} `)).toMatchObject({ leaf });
		expect(read(`Hash=${hash(leaf).toUpperCase()};${cert}`)).toMatchObject({ leaf });
		expect(read(`Subject= "a;b" ;${sum};${cert}`)).toMatchObject({ leaf });
	});

	it("refuses a key that comes twice, in any case or through an escape outside quotes", () => {
		const other = der(300, 3);
		expect(read(`${sum};${cert};cert="${encoded(block(other))}"`)).toBe("malformed");
		expect(read(`Subject=a\\;Cert=${encoded(block(other))};${sum};${cert}`)).toBe("malformed");
		expect(read(`${sum};${sum};${cert}`)).toBe("malformed");
		expect(read(`${sum};${cert};Subject=a;SUBJECT=b`)).toBe("malformed");
		expect(read(`${sum};${cert};Chain="${encoded(block(ca))}";Chain="${encoded(block(ca))}"`)).toBe(
			"malformed",
		);
	});

	it("refuses more than one element, repeated header lines among them, and an empty one", () => {
		expect(read(`${sum};${cert},${sum};${cert}`)).toBe("malformed");
		expect(read(`${sum};${cert}, By=spiffe://other`)).toBe("malformed");
		expect(read(`,${sum};${cert}`)).toBe("malformed");
		expect(read(`${sum};${cert},`)).toBe("malformed");
		expect(read("")).toBe("malformed");
	});

	it("refuses broken quoting and a field with no value", () => {
		for (const broken of [
			`Subject="open;${sum};${cert}`,
			`Subject="ends\\";${sum};${cert}`,
			`Subject=mid"dle;${sum};${cert}`,
			`Subject="closed"after;${sum};${cert}`,
			`Sub"ject=a;${sum};${cert}`,
			`Subject;${sum};${cert}`,
			`=x;${sum};${cert}`,
			`Subject="a"xy=c;${sum};${cert}`,
			`${sum};Cert=${encoded(block(leaf))};Subject="open`,
			`${sum};Cert=${encoded(block(leaf))};Subject="ends\\`,
			`${sum};${cert};`,
		]) {
			expect(read(broken), broken).toBe("malformed");
		}
	});

	it("takes a Cert of exactly one certificate block, URL-encoded, with a + kept as it is", () => {
		const plus = Uint8Array.from({ length: 300 }, () => 0xfb);
		const raw = `Hash=${hash(plus)};Cert=${encoded(block(plus)).replace(/%2B/g, "+")}`;
		expect(read(raw)).toMatchObject({ leaf: plus });
		for (const bad of [
			`${sum}`,
			`${sum};Cert=`,
			`${sum};Cert="${encoded(block(leaf) + block(ca))}"`,
			`${sum};Cert="${encoded(block(leaf, "PUBLIC KEY"))}"`,
			`${sum};Cert="${encoded(`text ${block(leaf)}`)}"`,
			`${sum};Cert="${encoded(block(leaf)).replace("%0A", "%zz")}"`,
			`${sum};Cert="${encoded(block(leaf).replace("-----\n", "-----\n*"))}"`,
		]) {
			expect(read(bad), bad).toBe("malformed");
		}
	});

	it("takes a Chain of certificate blocks only", () => {
		for (const bad of [
			block(ca, "PUBLIC KEY"),
			`${block(ca)}-----BEGIN CERTIFICATE-----\nAAAA\n`,
			`${block(ca)} junk`,
			"",
		]) {
			expect(read(`${sum};${cert};Chain="${encoded(bad)}"`), bad).toBe("malformed");
		}
	});

	it("holds the Cert to its Hash", () => {
		expect(read(cert)).toBe("malformed");
		expect(read(`Hash=${hash(ca)};${cert}`)).toBe("malformed");
		expect(read(`Hash=;${cert}`)).toBe("malformed");
		expect(read(`Hash=${hash(leaf).slice(0, 62)}zz;${cert}`)).toBe("malformed");
	});

	it("refuses a header past 16 KiB", () => {
		const padding = `Subject="${"x".repeat(16_384)}"`;
		expect(read(`${padding};${sum};${cert}`)).toBe("malformed");
	});
});
