import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { expect, it } from "vitest";
import type { PathPolicy } from "../contract.ts";
import { pathOf } from "../path.ts";
import { dns, type Issuing, ip, issue, subtree } from "./authority.ts";

const clientAuth = ["1.3.6.1.5.5.7.3.2"];
const policyOf = (anchors: Uint8Array[]): PathPolicy => ({
	anchors,
	maxIntermediates: 4,
	minRsaBits: 2048,
});

/** What becomes of a client under an intermediate under a root, each stating what it is given. */
async function reasonOf(
	root: Partial<Issuing>,
	intermediate: Partial<Issuing>,
	client: Partial<Issuing>,
) {
	const r = await issue({ cn: "root", ca: true, ...root });
	const i = await issue({ cn: "intermediate", by: r, ca: true, ...intermediate });
	const c = await issue({ cn: "client", by: i, eku: clientAuth, ...client });
	const read = await pathOf(c.der, [i.der], policyOf([r.der]), Date.now());
	return read.kind === "path" ? "valid" : read.reason;
}

it("holds every DNS name to the permitted subtrees, on label boundaries and in any case", async () => {
	const permitted = { permitted: [subtree(dns("Example.COM"))] };
	expect(await reasonOf({}, permitted, { san: [dns("a.example.com")] })).toBe("valid");
	expect(await reasonOf({}, permitted, { san: [dns("example.com")] })).toBe("valid");
	expect(await reasonOf({}, permitted, { san: [dns("A.EXAMPLE.com")] })).toBe("valid");
	expect(await reasonOf({}, permitted, { san: [dns("a.example.com"), dns("b.other.com")] })).toBe(
		"name constraints",
	);
	expect(await reasonOf({}, permitted, { san: [dns("badexample.com")] })).not.toBe("valid");
	expect(await reasonOf({}, permitted, {})).toBe("valid");
	expect(
		await reasonOf({}, permitted, { san: [dns("a.example.com"), dns("badexample.com")] }),
	).toBe("name constraints");
	expect(await reasonOf({}, permitted, { san: [dns("a.example.com"), ip(10, 0, 0, 1)] })).toBe(
		"valid",
	);
	const below = { permitted: [subtree(dns(".example.com"))] };
	expect(await reasonOf({}, below, { san: [dns("a.example.com")] })).toBe("valid");
	expect(await reasonOf({}, below, { san: [dns("example.com")] })).not.toBe("valid");
});

it("refuses any name an excluded subtree covers, whatever else it permits", async () => {
	const both = {
		permitted: [subtree(dns("example.com"))],
		excluded: [subtree(dns("bad.example.com"))],
	};
	expect(await reasonOf({}, both, { san: [dns("a.example.com")] })).toBe("valid");
	expect(
		await reasonOf({}, both, { san: [dns("a.example.com"), dns("x.bad.example.com")] }),
	).not.toBe("valid");
	expect(
		await reasonOf(
			{ excluded: [subtree(dns("example.com"))] },
			{},
			{ san: [dns("a.EXAMPLE.com")] },
		),
	).not.toBe("valid");
	// A name spelled with its root's dot is the same name.
	const bad = { excluded: [subtree(dns("bad.example.com"))] };
	expect(await reasonOf({}, bad, { san: [dns("x.bad.example.com.")] })).toBe("name constraints");
});

it("holds a name to every CA above it, so stacked permitted subtrees intersect", async () => {
	const root = { permitted: [subtree(dns("a.com"))] };
	const intermediate = { permitted: [subtree(dns("b.com"))] };
	// The engine takes one name per CA as enough; here each name must lie in both.
	expect(await reasonOf(root, intermediate, { san: [dns("x.a.com"), dns("y.b.com")] })).toBe(
		"name constraints",
	);
	expect(await reasonOf(root, intermediate, { san: [dns("x.b.com")] })).not.toBe("valid");
	const narrower = { permitted: [subtree(dns("x.a.com"))] };
	expect(await reasonOf(root, narrower, { san: [dns("y.x.a.com")] })).toBe("valid");
	// An intermediate's own names are held to the CAs above it.
	expect(await reasonOf(root, { san: [dns("ca.b.com")] }, { san: [dns("x.a.com")] })).not.toBe(
		"valid",
	);
});

it("holds IP addresses to networks of their own family", async () => {
	const ten = { permitted: [subtree(ip(10, 0, 0, 0, 255, 0, 0, 0))] };
	expect(await reasonOf({}, ten, { san: [ip(10, 1, 2, 3)] })).toBe("valid");
	expect(await reasonOf({}, ten, { san: [ip(10, 1, 2, 3), ip(11, 0, 0, 1)] })).toBe(
		"name constraints",
	);
	const v6 = [0x20, 0x01, 0x0d, 0xb8, ...new Array(12).fill(0)];
	expect(await reasonOf({}, ten, { san: [ip(10, 1, 2, 3), ip(...v6)] })).not.toBe("valid");
	const excluded = { excluded: [subtree(ip(10, 0, 0, 0, 255, 0, 0, 0))] };
	expect(await reasonOf({}, excluded, { san: [ip(10, 9, 9, 9)] })).not.toBe("valid");
	expect(await reasonOf({}, excluded, { san: [ip(192, 0, 2, 1)] })).toBe("valid");
	expect(
		await reasonOf({}, { permitted: [subtree(ip(10, 0, 0, 0))] }, { san: [ip(10, 0, 0, 1)] }),
	).not.toBe("valid");
});

it("refuses a path whose constraints name a kind it does not judge, or bound a subtree's depth", async () => {
	const name = new pkijs.RelativeDistinguishedNames({
		typesAndValues: [
			new pkijs.AttributeTypeAndValue({
				type: "2.5.4.10",
				value: new asn1js.Utf8String({ value: "Example" }),
			}),
		],
	});
	// Kinds the client has no name of, or a name it lies outside of: the engine takes them.
	const unsupported = [
		{ excluded: [subtree(new pkijs.GeneralName({ type: 4, value: name }))] },
		{ permitted: [subtree(new pkijs.GeneralName({ type: 1, value: "example.com" }))] },
		{ excluded: [subtree(new pkijs.GeneralName({ type: 1, value: "example.com" }))] },
		{ permitted: [subtree(new pkijs.GeneralName({ type: 6, value: "example.com" }))] },
		{ excluded: [subtree(new pkijs.GeneralName({ type: 6, value: "example.com" }))] },
	];
	unsupported.push({ permitted: [subtree(ip(10, 0, 0, 0))] });
	for (const constraints of unsupported) {
		expect(await reasonOf({}, constraints, {})).toBe("name constraints unsupported");
		expect(await reasonOf(constraints, {}, {})).toBe("name constraints unsupported");
	}
	expect(await reasonOf({}, { permitted: [subtree(dns("example.com"), { minimum: 1 })] }, {})).toBe(
		"name constraints unsupported",
	);
	// A minimum past 4 bytes, which asn1js reads as 0 by its valueDec: refused by its value, 2^32 here.
	const wide = new asn1js.Integer({ valueHex: new Uint8Array([1, 0, 0, 0, 0]).buffer });
	expect(
		await reasonOf({}, { permitted: [subtree(dns("example.com"), { minimum: wide })] }, {}),
	).toBe("name constraints unsupported");
	// A zero written in more bytes than it needs is still zero: taken.
	const zero = new asn1js.Integer({ valueHex: new Uint8Array([0, 0, 0, 0, 0]).buffer });
	expect(
		await reasonOf({}, { permitted: [subtree(dns("example.com"), { minimum: zero })] }, {}),
	).not.toBe("name constraints unsupported");
	expect(await reasonOf({}, { permitted: [subtree(dns("example.com"), { maximum: 2 })] }, {})).toBe(
		"name constraints unsupported",
	);
});

it("holds no self-issued CA's names to the constraints above it, but holds a self-issued leaf's", async () => {
	const permitted = { permitted: [subtree(dns("example.com"))] };
	// A rollover: the root's name, issued under the root.
	const rollover = { cn: "root", san: [dns("ca.other.org")] };
	expect(await reasonOf(permitted, rollover, { san: [dns("a.example.com")] })).toBe("valid");
	expect(await reasonOf(permitted, rollover, { san: [dns("a.other.org")] })).toBe(
		"name constraints",
	);
	const leaf = { cn: "intermediate", san: [dns("a.example.com"), dns("a.other.org")] };
	expect(await reasonOf({}, permitted, leaf)).toBe("name constraints");
});

it("holds no name to an excluded subtree of another kind, whatever the name's text", async () => {
	const network = ip(10, 0, 0, 0, 255, 0, 0, 0);
	const excluded = { excluded: [subtree(network)] };
	expect(await reasonOf({}, excluded, { san: [dns(`x.${String(network.value)}`)] })).toBe("valid");
	const named = { excluded: [subtree(dns("example.com"))] };
	expect(await reasonOf({}, named, { san: [ip(10, 1, 2, 3)] })).toBe("valid");
});
