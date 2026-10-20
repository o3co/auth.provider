import { expect, it } from "vitest";
import { withinHosts } from "../src/contract.ts";

it("tells whether a URL's host is among the hosts, matched as outbound matches them", () => {
	const hosts = ["idp.example", ".cdn.example", "[2001:DB8::1]"];
	for (const url of [
		"https://IDP.example/authorize",
		"https://idp.example./token",
		"https://keys.cdn.example/jwks",
		"https://cdn.example/jwks",
		"https://[2001:db8::1]/x",
	]) {
		expect(withinHosts(url, hosts), url).toBe(true);
	}
	for (const url of [
		"https://other.example/",
		"https://idp.example.evil/",
		"not a url",
		"https://xn--idp-.example/",
	]) {
		expect(withinHosts(url, hosts), url).toBe(false);
	}
	expect(withinHosts("https://idp.example/", [])).toBe(false);
	expect(withinHosts("https://keys.cdn.example/", ["*.cdn.example"])).toBe(false);
});
