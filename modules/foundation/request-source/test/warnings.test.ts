import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { determinedSource, ignoredForwarding, proxiesOf } from "../src/contract.ts";

const proxies = proxiesOf({ "trusted-proxies": ["10.0.0.1"], "proxy-hops": 1 });
const forwarded = new Map([["x-forwarded-for", "198.51.100.1"]]);

it("warns of X-Forwarded-For from a peer it does not trust, at most once a minute", () => {
	let now = 0;
	const warns = ignoredForwarding(proxies, quietRuntime({ clock: { now: () => now } }).clock);
	expect([warns("203.0.113.9", forwarded), warns("203.0.113.9", forwarded)]).toEqual([true, false]);
	now = 60_000;
	expect(warns("203.0.113.9", forwarded)).toBe(false);
	now = 60_001;
	expect(warns("203.0.113.9:1111", forwarded)).toBe(true);
});

it("does not warn of a trusted proxy's forwarding, or of a request without it", () => {
	const warns = ignoredForwarding(proxies, quietRuntime().clock);
	expect(warns("10.0.0.1", forwarded)).toBe(false);
	expect(warns("::ffff:10.0.0.1", forwarded)).toBe(false);
	expect(warns("10.0.0.1:1111", forwarded)).toBe(false);
	expect(warns("203.0.113.9", new Map())).toBe(false);
});

it("answers a request's source only when it was determined", () => {
	const source = { address: "198.51.100.9", scheme: "https", determined: true } as const;
	expect(determinedSource({ source })).toBe("198.51.100.9");
	expect(determinedSource({ source: { ...source, determined: false } })).toBeUndefined();
});
