import { expect, it } from "vitest";
import { certificateOf } from "../src/certificate.ts";

const der = (n: number) => Uint8Array.from({ length: n }, (_, i) => (i * 7) % 256);
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");
const pem = (bytes: Uint8Array) =>
	`-----BEGIN CERTIFICATE-----\n${b64(bytes).replace(/.{64}/g, "$&\n")}\n-----END CERTIFICATE-----\n`;
const headers = (h: Record<string, string>) => new Map(Object.entries(h));
const rfc9440 = {
	dialect: "rfc9440" as const,
	header: "client-cert",
	"chain-header": "client-cert-chain",
};
const nginx = { dialect: "pem" as const, header: "x-client-cert" };
const found = (leaf: Uint8Array, chain: Uint8Array[] = []) => ({
	kind: "certificate",
	leaf,
	chain,
});
const pemRead = (value: string) => certificateOf(headers({ "x-client-cert": value }), nginx);

it("reads RFC 9440's byte sequences, the leaf and the chain behind it", () => {
	const [leaf, ca] = [der(300), der(200)];
	const read = certificateOf(
		headers({
			"client-cert": `:${b64(leaf)}:`,
			"client-cert-chain": `:${b64(ca)}:, :${b64(leaf)}:`,
		}),
		rfc9440,
	);
	expect(read).toEqual(found(leaf, [ca, leaf]));
	expect(certificateOf(headers({}), rfc9440)).toEqual({ kind: "none" });
	expect(certificateOf(headers({ "client-cert": `:${b64(leaf)}:` }), rfc9440)).toEqual(found(leaf));
});

it("reads one PEM block, URL-encoded or not", () => {
	const leaf = der(300);
	expect(pemRead(encodeURIComponent(pem(leaf)))).toEqual(found(leaf));
	expect(pemRead(pem(leaf).replace(/\n/g, " "))).toEqual(found(leaf));
});

it("refuses a PEM header holding anything beside its one block", () => {
	const leaf = der(300);
	for (const bad of [
		`junk ${pem(leaf)}`,
		`${pem(leaf)} junk`,
		`-----BEGIN CERTIFICATE-----\nAAAA\n${pem(leaf)}`,
		`${pem(leaf)}-----END CERTIFICATE-----`,
		encodeURIComponent(`x${pem(leaf)}`),
	]) {
		expect(pemRead(bad), bad).toEqual({ kind: "malformed" });
	}
});

it("takes no certificate from a header it cannot read, or one past the size it allows", () => {
	const leaf = der(300);
	for (const bad of [
		`${b64(leaf)}`,
		`:${b64(leaf)}`,
		`:not base64!:`,
		`::`,
		`:${b64(leaf)}:, :${b64(leaf)}:`,
		`:${b64(der(50_000))}:`,
		":A:",
		":AA=A:",
		":AAAA===:",
	]) {
		expect(certificateOf(headers({ "client-cert": bad }), rfc9440), bad).toEqual({
			kind: "malformed",
		});
	}
	for (const chain of ["nope", ":A:", `:${b64(der(13_000))}:`]) {
		const sent = headers({ "client-cert": `:${b64(leaf)}:`, "client-cert-chain": chain });
		expect(certificateOf(sent, rfc9440), chain.slice(0, 10)).toEqual({ kind: "malformed" });
	}
	for (const bad of [`${pem(leaf)}${pem(leaf)}`, "not a pem", "x".repeat(16_385)]) {
		expect(pemRead(bad), bad).toEqual({ kind: "malformed" });
	}
});

it("reads a header of exactly 16 KiB, and refuses one a character longer", () => {
	// 12,285 bytes are 16,380 base64 characters; with the colons and two spaces, 16,384 in all.
	const leaf = der(12_285);
	const item = `:${b64(leaf)}:`;
	expect(certificateOf(headers({ "client-cert": `  ${item}` }), rfc9440)).toEqual(found(leaf));
	expect(certificateOf(headers({ "client-cert": `   ${item}` }), rfc9440)).toEqual({
		kind: "malformed",
	});
});

it("hands on a certificate no reader can change", () => {
	const read = certificateOf(headers({ "client-cert": `:${b64(der(300))}:` }), rfc9440);
	expect(Object.isFrozen(read)).toBe(true);
	expect(read.kind === "certificate" && Object.isFrozen(read.chain)).toBe(true);
});
