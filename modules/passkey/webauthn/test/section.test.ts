import { expect, it } from "vitest";
import webauthnModule from "../src/module.ts";
import { section } from "../src/section.ts";

const accepts = (rpId: string, origins: string[]) =>
	section.safeParse({ "rp-id": rpId, "rp-name": "RP", origins }).success;

it("takes a relying party ID equal to each origin's host, or a domain each one lies under", () => {
	expect(accepts("rp.example", ["https://rp.example", "https://login.rp.example"])).toBe(true);
	expect(accepts("localhost", ["http://localhost:3000"])).toBe(true);
	expect(accepts("login.rp.example", ["https://login.rp.example"])).toBe(true);
});

it("refuses a relying party ID some origin's host does not end in, at a label", () => {
	expect(accepts("rp.example", ["https://rp.example", "https://evil.example"])).toBe(false);
	expect(accepts("rp.example", ["https://notrp.example"])).toBe(false);
	expect(accepts("login.rp.example", ["https://rp.example"])).toBe(false);
	expect(accepts("RP.example", ["https://rp.example"])).toBe(false);
	expect(accepts("rp.example.", ["https://rp.example"])).toBe(false);
});

it("refuses a single label above an origin's host, which a browser holds a public suffix", () => {
	expect(accepts("example", ["https://rp.example"])).toBe(false);
});

const app = "android:apk-key-hash:pNiP5iKyQ8JwgLTSKGZmcRHqvOUP1qGP8FfEcCQPvVI";

it("takes an Android app origin beside the web ones, with no host to match the relying party ID", () => {
	expect(accepts("rp.example", ["https://rp.example", app])).toBe(true);
	expect(accepts("rp.example", [`android:apk-key-hash:-_${"a".repeat(40)}A`])).toBe(true);
});

it("refuses an Android app origin not written as the unpadded base64url SHA-256 alone", () => {
	for (const entry of [
		`${app}=`,
		app.slice(0, -1),
		`${app}A`,
		`${app.slice(0, -1)}J`,
		`android:apk-key-hash:${"9A".repeat(32)}`,
		`${app}/path`,
		"android:apk-key-hash:",
		app.replace("android:", "Android:"),
		app.replace("-key-", "-KEY-"),
	]) {
		expect(accepts("rp.example", ["https://rp.example", entry]), entry).toBe(false);
	}
});

it("refuses an Android app origin as a top origin, since nothing frames an app", () => {
	const parsed = section.safeParse({
		"rp-id": "rp.example",
		"rp-name": "RP",
		origins: ["https://rp.example"],
		"top-origins": [app],
	});
	expect(parsed.success).toBe(false);
});

const parsed = (more: object) =>
	section.safeParse({
		"rp-id": "rp.example",
		"rp-name": "RP",
		origins: ["https://rp.example"],
		...more,
	});

it("takes a challenge lifetime from 10s to 10m, written with its unit", () => {
	const takes = (value: unknown) => parsed({ "challenge-lifetime": value }).success;
	expect(["9s", "10s", "10m", "601s", 120, "120"].map(takes)).toEqual([
		false,
		true,
		true,
		false,
		false,
		false,
	]);
});

it("frames nothing, keeps a challenge 2m and takes every algorithm where nothing is set", () => {
	expect(parsed({}).data).toEqual({
		"rp-id": "rp.example",
		"rp-name": "RP",
		origins: ["https://rp.example"],
		"top-origins": [],
		"challenge-lifetime": 120,
		algorithms: ["EdDSA", "ES256", "RS256"],
	});
});

it("takes the algorithms named, in their order, and refuses none, one it cannot verify, or one named twice", () => {
	expect(parsed({ algorithms: ["RS256", "ES256"] }).data?.algorithms).toEqual(["RS256", "ES256"]);
	for (const algorithms of [[], ["ES384"], ["es256"], [-7], ["ES256", "ES256"]]) {
		expect(parsed({ algorithms }).success, JSON.stringify(algorithms)).toBe(false);
	}
});

it("refuses the keys passkeys keeps now, naming each", () => {
	for (const key of ["user-verification", "max-credentials"]) {
		expect(parsed({ [key]: key === "max-credentials" ? 10 : "preferred" }).success, key).toBe(
			false,
		);
	}
});

it("refuses the challenge lifetime by its name in seconds", () => {
	expect(parsed({ "challenge-seconds": 120 }).success).toBe(false);
});

it("refuses in production an origin over plain http on localhost, in either list", () => {
	const ask = (origins: string[], top: string[] = []) =>
		webauthnModule
			.refusedInProduction?.({ origins, "top-origins": top } as never)
			?.map((r) => r.key);
	expect(ask(["http://localhost:3000"], ["http://localhost:4000"])).toEqual([
		"origins",
		"top-origins",
	]);
	expect(ask(["https://as.example"], ["https://top.example"])).toEqual([]);
});
