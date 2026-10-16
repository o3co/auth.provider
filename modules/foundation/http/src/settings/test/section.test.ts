import { expect, it } from "vitest";
import { section } from "../section.ts";

const parses = (settings: Record<string, unknown>) => section.safeParse(settings).success;

it("takes the trusted proxies and hops by request-source's part, under the same keys", () => {
	expect(parses({ "trusted-proxies": ["10.0.0.0/8", "2001:db8::1"] })).toBe(true);
	expect(parses({ "trusted-proxies": ["10.0.0.0/08"] })).toBe(false);
	expect([1, 10, 0, 11].map((hops) => parses({ "proxy-hops": hops }))).toEqual([
		true,
		true,
		false,
		false,
	]);
	expect(section.parse({})).toMatchObject({ "trusted-proxies": [], "proxy-hops": 1 });
});

it("listens on the IPv4 loopback address unless told otherwise", () => {
	expect(section.parse({}).host).toBe("127.0.0.1");
});

it("takes a port up to 65535, and the client's certificate by client-certificate's part", () => {
	expect([65_535, 65_536].map((port) => parses({ port }))).toEqual([true, false]);
	const named = (header: string) => parses({ "client-certificate": { dialect: "pem", header } });
	expect([named("x-client-cert"), named("X-Client-Cert")]).toEqual([true, false]);
	expect(section.parse({})["client-certificate"]).toBeUndefined();
});
