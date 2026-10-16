import { expect, it } from "vitest";
import { certificateSettings } from "../src/contract.ts";

const takes = (settings: unknown) => certificateSettings.safeParse(settings).success;

it("names a dialect and its headers, lower case, with no default header for pem", () => {
	expect(certificateSettings.parse({ dialect: "rfc9440" })).toEqual({
		dialect: "rfc9440",
		header: "client-cert",
		"chain-header": "client-cert-chain",
	});
	expect(certificateSettings.parse({ dialect: "xfcc" })).toEqual({
		dialect: "xfcc",
		header: "x-forwarded-client-cert",
	});
	expect([takes({ dialect: "pem", header: "x-client-cert" }), takes({ dialect: "pem" })]).toEqual([
		true,
		false,
	]);
	for (const bad of [
		{ dialect: "der" },
		{ dialect: "rfc9440", header: "X-Client-Cert" },
		{ dialect: "rfc9440", header: "Bad Name" },
		{ dialect: "xfcc", "chain-header": "x-chain" },
	]) {
		expect(takes(bad), JSON.stringify(bad)).toBe(false);
	}
});
