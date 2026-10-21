import { expect, it } from "vitest";
import { browsedRefusalText, destinationRefusal, type OutboundRefusals } from "../src/contract.ts";

/** Refusals explaining every URL on `bad.example` as not allowed, and naming what they were asked. */
const asked: { url: string; narrower: unknown }[] = [];
const refusals: OutboundRefusals = {
	explained: (url, narrower) => {
		asked.push({ url, narrower });
		return new URL(url).hostname === "bad.example" ? "not-allowed: name it" : undefined;
	},
};

it("says a refused destination as every module does, naming what is refused, and nothing for one let through", () => {
	expect(destinationRefusal(refusals, "https://bad.example/x")).toBe(
		"outbound's destination policy refuses it: not-allowed: name it",
	);
	expect(
		destinationRefusal(
			refusals,
			"https://bad.example/k",
			{ hosts: ["bad.example"] },
			"the jwks-uri",
		),
	).toBe("outbound's destination policy refuses the jwks-uri: not-allowed: name it");
	expect(destinationRefusal(refusals, "https://ok.example/")).toBeUndefined();
	expect(asked.map((a) => a.narrower)).toEqual([undefined, { hosts: ["bad.example"] }, undefined]);
});

it("says a refused URL the browser goes to as every module does, and takes https where the policy does not say", () => {
	const told: OutboundRefusals = {
		explained: () => undefined,
		browsedRefusal: (url) => (url.startsWith("http:") ? "plain http: set it" : undefined),
	};
	expect(browsedRefusalText(told, "http://idp.example/a", {}, "the authorization endpoint")).toBe(
		"outbound's policy for what the browser goes to refuses the authorization endpoint: plain http: set it",
	);
	expect(browsedRefusalText(told, "https://idp.example/a")).toBeUndefined();
	const silent: OutboundRefusals = { explained: () => undefined };
	expect(browsedRefusalText(silent, "https://idp.example/a")).toBeUndefined();
	expect(browsedRefusalText(silent, "http://127.0.0.1/a")).toMatch(
		/^outbound's policy for what the browser goes to refuses it: /,
	);
});
