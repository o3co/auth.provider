import { expect, it } from "vitest";
import { anchorOf, revocationPolicyOf, section } from "../src/section.ts";

const revocationOf = (stated: Record<string, unknown>) => {
	const parsed = section.parse({
		mode: "pki",
		anchors: ["x"],
		"min-rsa-bits": 3072,
		revocation: stated,
	});
	if (parsed.mode !== "pki" || parsed.revocation.mode === "disabled")
		throw new Error("not checked");
	return revocationPolicyOf(parsed.revocation);
};

it("states the revocation policy in milliseconds, with the defaults the legacy system held", () => {
	const base = { "on-unavailable": "reject", hosts: ["ca.example"] };
	expect(revocationOf({ mode: "both", ...base })).toEqual({
		mode: "both",
		nonce: true,
		skewMs: 300_000,
		ocspFreshMs: 600_000,
		crlTtlMs: 3_600_000,
		failureMs: 30_000,
		crlEntries: 256,
		ocspEntries: 1024,
		maxFetches: 4,
	});
	expect(
		revocationOf({
			mode: "ocsp",
			...base,
			nonce: false,
			skew: "1s",
			"ocsp-fresh": "2s",
			"crl-ttl": "3s",
			"failure-lifetime": "4s",
			"crl-entries": 5,
			"ocsp-entries": 6,
			"max-fetches": 7,
		}),
	).toEqual({
		mode: "ocsp",
		nonce: false,
		skewMs: 1000,
		ocspFreshMs: 2000,
		crlTtlMs: 3000,
		failureMs: 4000,
		crlEntries: 5,
		ocspEntries: 6,
		maxFetches: 7,
	});
});

it("holds a path to four intermediates and 2048-bit RSA keys unless stated, and to fourteen at most", () => {
	const stated = (more: Record<string, unknown>) =>
		section.safeParse({ mode: "pki", anchors: ["x"], revocation: { mode: "disabled" }, ...more });
	expect(stated({}).data).toMatchObject({ "max-intermediates": 4, "min-rsa-bits": 2048 });
	expect(stated({ "max-intermediates": 14 }).success).toBe(true);
	expect(stated({ "max-intermediates": 15 }).success).toBe(false);
});

it("reads no anchor from text without a certificate block", () => {
	expect(anchorOf("   ")).toBeUndefined();
});

it("takes revocation hosts as host-entries reads a host list, and refuses anything else", () => {
	const parsedWith = (hosts: readonly string[]) =>
		section.safeParse({
			mode: "pki",
			anchors: ["x"],
			"min-rsa-bits": 3072,
			revocation: { mode: "crl", "on-unavailable": "reject", hosts },
		}).success;
	expect(parsedWith(["ca.example", ".pki.example", "10.0.0.1"])).toBe(true);
	for (const entry of ["*.pki.example", "ca.example.", "bad host", "ca_x.example", "10.5"]) {
		expect(parsedWith([entry]), entry).toBe(false);
	}
});

it("takes a revocation host in another script, its marks included, and refuses an address with a zone", () => {
	const parsedWith = (hosts: readonly string[]) =>
		section.safeParse({
			mode: "pki",
			anchors: ["x"],
			"min-rsa-bits": 3072,
			revocation: { mode: "crl", "on-unavailable": "reject", hosts },
		}).success;
	expect(parsedWith(["कि.example"])).toBe(true);
	expect(parsedWith(["fe80::1%eth0"])).toBe(false);
});

it("reads each revocation time written with its unit, within its bounds, and refuses a bare number", () => {
	const takes = (more: Record<string, unknown>) =>
		section.safeParse({
			mode: "pki",
			anchors: ["x"],
			revocation: { mode: "crl", "on-unavailable": "reject", hosts: ["ca.example"], ...more },
		}).success;
	expect(
		[{ skew: "0s" }, { skew: "1h" }, { timeout: "1ms" }, { timeout: "1m" }].map(takes),
	).toEqual([true, true, true, true]);
	expect([{ skew: "61m" }, { timeout: "0ms" }, { timeout: "61s" }].map(takes)).toEqual([
		false,
		false,
		false,
	]);
	for (const key of ["skew", "ocsp-fresh", "crl-ttl", "failure-lifetime", "timeout"]) {
		expect([takes({ [key]: 30 }), takes({ [key]: "30" })], key).toEqual([false, false]);
	}
});
