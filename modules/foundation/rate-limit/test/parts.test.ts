import { testRequest } from "@mod/http/testing";
import { quietLog } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { retryAfterMs } from "../src/partition.ts";
import { limitingAttempts, limitingRequests, uncountedCounter } from "../src/per-source.ts";
import { sourceKey } from "../src/source.ts";

it("keys IPv4 by address and IPv6 by its /64, however the address is written", () => {
	expect(sourceKey("198.51.100.4")).toBe("198.51.100.4");
	expect(sourceKey("2001:db8:1:2:3:4:5:6")).toBe("2001:db8:1:2::/64");
	expect(sourceKey("2001:db8:1:2::9")).toBe("2001:db8:1:2::/64");
	expect(sourceKey("2001:db8::9")).toBe("2001:db8:0:0::/64");
	expect(sourceKey("::1")).toBe("0:0:0:0::/64");
});

it("hints a wait of at least a second, and never longer than the window", () => {
	const window = { limit: 1, ms: 60_000 };
	expect(retryAfterMs(window, 1_500, 1_000)).toBe(1_000);
	expect(retryAfterMs(window, 31_000, 1_000)).toBe(30_000);
	expect(retryAfterMs(window, 999_000, 1_000)).toBe(60_000);
});

it("throws a counting failure other than unavailable, so a fault never lets a request by", async () => {
	const failing = {
		hit: async () => {
			throw new TypeError("a fault");
		},
	};
	const told = {
		log: quietLog,
		recorded: { record: () => {} },
		uncounted: uncountedCounter(),
	};
	const request = testRequest({ source: { address: "198.51.100.4", determined: true } });
	const options = { name: "n", window: { limit: 1, ms: 1000 } };
	for (const policy of [
		limitingAttempts(failing, told),
		limitingRequests(failing, told, "open"),
		limitingRequests(failing, told, "closed"),
	]) {
		await expect(Promise.resolve(policy.apply(request, options))).rejects.toThrow(TypeError);
	}
});
