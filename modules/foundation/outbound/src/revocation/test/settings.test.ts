import { expect, it } from "vitest";
import { revocationSection, startWarnings } from "../settings.ts";

it("warns at every start that no peer's revocation is checked while no CRL host is listed, and that an unconfirmed one is taken where accepted, by a reason alone", () => {
	const warned = (stated: Record<string, unknown>) =>
		startWarnings(revocationSection.parse(stated)).map(([event]) => event);
	expect(warned({})).toEqual(["outbound.revocation_unchecked"]);
	expect(warned({ hosts: ["crl.example"] })).toEqual([]);
	expect(warned({ hosts: ["crl.example"], "accept-unconfirmed": true })).toEqual([
		"outbound.revocation_unconfirmed_accepted",
	]);
	expect(
		JSON.stringify(
			startWarnings(
				revocationSection.parse({ hosts: ["crl.example"], "accept-unconfirmed": true }),
			),
		),
	).not.toContain("crl.example");
});

it("keeps 64 issuers' CRLs unless stated, from 1 to 1,024, and times written with their unit", () => {
	const parsed = revocationSection.safeParse;
	expect(parsed({}).data).toEqual({
		hosts: [],
		"accept-unconfirmed": false,
		"crl-entries": 64,
		"failure-lifetime": 30_000,
		"crl-ttl": 3_600_000,
	});
	expect(parsed({ "crl-entries": 1024 }).success).toBe(true);
	expect(parsed({ "crl-entries": 1025 }).success).toBe(false);
	expect(parsed({ "crl-entries": 0 }).success).toBe(false);
	expect(parsed({ "crl-ttl": "2d" }).success).toBe(false);
	expect(parsed({ "failure-lifetime": "500ms" }).success).toBe(false);
	expect(parsed({ other: true }).success).toBe(false);
});
