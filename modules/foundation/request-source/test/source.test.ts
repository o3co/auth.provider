import { expect, it } from "vitest";
import { proxiesOf, sourceOf } from "../src/contract.ts";
import { canonical } from "../src/source.ts";

const proxies = (blocks: string[], hops = 1) =>
	proxiesOf({ "trusted-proxies": blocks, "proxy-hops": hops });
const headers = (h: Record<string, string>) => new Map(Object.entries(h));
const der = Uint8Array.from([48, 3, 2, 1, 1]);
const sent = headers({ "client-cert": `:${Buffer.from(der).toString("base64")}:` });
const trusted = proxiesOf(
	{ "trusted-proxies": ["10.0.0.1"], "proxy-hops": 1 },
	{ dialect: "rfc9440", header: "client-cert" },
);

it("writes addresses in one canonical form, from bare addresses or ones with ports", () => {
	expect(canonical("2001:DB8:0:0:0:0:0:1")).toBe("2001:db8::1");
	expect(canonical("[2001:db8::1]:443")).toBe("2001:db8::1");
	expect(canonical("fe80::1%eth0")).toBe("fe80::1");
	expect(canonical("::ffff:203.0.113.9")).toBe("203.0.113.9");
	expect(canonical("::FFFF:cb00:7109")).toBe("203.0.113.9");
	expect(canonical("203.0.113.9:1111")).toBe("203.0.113.9");
	expect(canonical(" 203.0.113.9 ")).toBe("203.0.113.9");
	for (const bad of ["", "not-an-ip", "203.0.113.9:", "unknown", "[::1"])
		expect(canonical(bad)).toBeUndefined();
});

it("ignores forwarded headers from a peer it does not trust", () => {
	const s = sourceOf(
		proxies([]),
		"203.0.113.9",
		headers({ "x-forwarded-for": "198.51.100.1", "x-forwarded-proto": "https" }),
	);
	expect(s).toEqual({ address: "203.0.113.9", scheme: "http", determined: true });
});

it("takes the sender and scheme from trusted proxies, walking at most the configured hops", () => {
	const fwd = headers({
		"x-forwarded-for": "198.51.100.1, 10.0.0.2:5000",
		"x-forwarded-proto": "https",
	});
	expect(sourceOf(proxies(["10.0.0.0/8"]), "10.0.0.1", fwd)).toEqual({
		address: "10.0.0.2",
		scheme: "https",
		determined: false,
	});
	expect(sourceOf(proxies(["10.0.0.0/8"], 2), "10.0.0.1", fwd)).toEqual({
		address: "198.51.100.1",
		scheme: "https",
		determined: true,
	});
	expect(sourceOf(proxies(["10.0.0.0/8"], 3), "::ffff:10.0.0.1", fwd).address).toBe("198.51.100.1");
	expect(
		sourceOf(proxies(["::1"]), "::1", headers({ "x-forwarded-for": "[2001:DB8::1]:443" })).address,
	).toBe("2001:db8::1");
});

it("stops at a forwarded value that is not an address, skips empty ones, and reads the scheme in any case", () => {
	const twice = proxies(["127.0.0.1"], 2);
	const garbage = headers({ "x-forwarded-for": "198.51.100.1, unknown" });
	expect(sourceOf(twice, "127.0.0.1", garbage)).toMatchObject({
		address: "127.0.0.1",
		determined: false,
	});
	const trailing = headers({ "x-forwarded-for": "198.51.100.1, ", "x-forwarded-proto": "HTTPS" });
	const source = sourceOf(proxies(["127.0.0.1"]), "127.0.0.1", trailing);
	expect(source).toEqual({ address: "198.51.100.1", scheme: "https", determined: true });
	expect(Object.isFrozen(source)).toBe(true);
});

it("leaves the sender undetermined when a trusted proxy gives no usable address", () => {
	for (const h of [{}, { "x-forwarded-for": "unknown" }, { forwarded: "for=198.51.100.1" }]) {
		const s = sourceOf(proxies(["127.0.0.1"]), "127.0.0.1", headers(h));
		expect([s.address, s.determined]).toEqual(["127.0.0.1", false]);
	}
	expect(
		sourceOf(proxies(["127.0.0.1"]), "127.0.0.1", headers({ "x-forwarded-proto": "https, http" }))
			.scheme,
	).toBe("http");
});

it("takes the client's certificate only from a trusted peer, and only where the operator names the header [rfc8705-3-a] [rfc8705-3-e]", () => {
	expect(sourceOf(trusted, "10.0.0.1", sent).clientCertificate).toMatchObject({ leaf: der });
	expect(sourceOf(trusted, "203.0.113.9", sent).clientCertificate).toBeUndefined();
	expect(sourceOf(proxies(["10.0.0.1"]), "10.0.0.1", sent).clientCertificate).toBeUndefined();
});

it("hands on what a trusted proxy forwarded: the certificate, or that it was not readable", () => {
	expect(sourceOf(trusted, "10.0.0.1", sent).clientCertificate).toEqual({
		kind: "certificate",
		leaf: der,
		chain: [],
	});
	const malformed = headers({ "client-cert": "nope" });
	expect(sourceOf(trusted, "10.0.0.1", malformed).clientCertificate).toEqual({ kind: "malformed" });
	expect(sourceOf(trusted, "203.0.113.9", malformed).clientCertificate).toBeUndefined();
	expect(sourceOf(trusted, "10.0.0.1", headers({})).clientCertificate).toBeUndefined();
	const forwarded = sourceOf(trusted, "10.0.0.1", sent).clientCertificate;
	expect(Object.isFrozen(forwarded)).toBe(true);
	expect(forwarded?.kind === "certificate" && Object.isFrozen(forwarded.chain)).toBe(true);
});

it("writes the direct peer's address in canonical form, and trusts it with a port", () => {
	expect(sourceOf(proxies([]), "::FFFF:203.0.113.9", headers({})).address).toBe("203.0.113.9");
	const fwd = headers({ "x-forwarded-for": "198.51.100.1" });
	expect(sourceOf(proxies(["10.0.0.1"]), "10.0.0.1:1111", fwd)).toMatchObject({
		address: "198.51.100.1",
		determined: true,
	});
});

it("reads a single forwarded scheme with spaces around it", () => {
	const proto = headers({ "x-forwarded-proto": " https " });
	expect(sourceOf(proxies(["127.0.0.1"]), "127.0.0.1", proto).scheme).toBe("https");
});
