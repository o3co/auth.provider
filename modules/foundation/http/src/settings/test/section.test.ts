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

it("reads every default when the operator sets nothing", () => {
	expect(section.parse({})).toEqual({
		host: "127.0.0.1",
		port: 8080,
		"trusted-proxies": [],
		"cors-origins": [],
		"insecure-origin": false,
		"proxy-hops": 1,
		"headers-timeout": 10,
		"request-timeout": 30,
		"max-connections": 10_000,
	});
});

it("takes the two timeouts written with their unit, within their bounds, the headers' no longer than the request's", () => {
	const both = (headers: string, request: string) =>
		parses({ "headers-timeout": headers, "request-timeout": request });
	expect([both("1s", "1s"), both("1m", "5m"), both("0s", "5s"), both("61s", "5m")]).toEqual([
		true,
		true,
		false,
		false,
	]);
	expect([both("10s", "301s"), both("20s", "10s")]).toEqual([false, false]);
	expect([parses({ "headers-timeout": 10 }), parses({ "request-timeout": "30" })]).toEqual([
		false,
		false,
	]);
});

it("holds from 1 to 1000000 connections at once", () => {
	const held = (n: number) => parses({ "max-connections": n });
	expect([held(0), held(1), held(1_000_000), held(1_000_001)]).toEqual([false, true, true, false]);
});
