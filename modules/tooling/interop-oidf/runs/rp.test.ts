import { describe, expect, it } from "vitest";
import { clientTitleOf, runClientPlan } from "../src/client-plan/client-plan.ts";
import { clientPlans } from "../src/plans.ts";
import { reportRun } from "../src/report/vitest.ts";

// The plan runs as the file is read: each suite test is a test of its own, and the app's side of
// each beside it, under the items it shows.
const plan = clientPlans.rp;
const ran = await runClientPlan(plan);
reportRun(clientTitleOf(plan), ran.run);

const outcomeOf = (test: string) => ran.run.modules.find((m) => m.testModule === test)?.outcome;
/** The suite passed the test, and the app logged the browser in as the user its subject is linked to. */
const loggedIn = (test: string) => {
	expect(outcomeOf(test), test).toEqual({ kind: "passed" });
	expect(ran.sides[test], test).toMatchObject({
		booted: true,
		returned: true,
		subject: ran.subject,
	});
};
/** The suite passed the test, and the app answered its callback without logging the browser in. */
const refused = (test: string) => {
	expect(outcomeOf(test), test).toEqual({ kind: "passed" });
	const side = ran.sides[test];
	expect(side, test).toMatchObject({ booted: true, returned: false });
	expect(side?.subject, test).toBeUndefined();
};
/** The suite passed the test, the app started for it and asked nothing more. */
const startedOnly = (test: string) => {
	expect(outcomeOf(test), test).toEqual({ kind: "passed" });
	expect(ran.sides[test], test).toMatchObject({ booted: true, returned: false });
};
/** The suite passed the test, and the app refused to start on what the upstream described. */
const refusedToStart = (test: string) => {
	expect(outcomeOf(test), test).toEqual({ kind: "passed" });
	expect(ran.sides[test], test).toMatchObject({ booted: false, returned: false });
};

describe("the provider as a relying party, through the suite's OP: logging in", () => {
	it("logs a browser in through the suite's OP, reading its UserInfo", () => {
		for (const test of [
			"oidcc-client-test",
			"oidcc-client-test-client-secret-basic",
			"oidcc-client-test-scope-userinfo-claims",
			"oidcc-client-test-userinfo-bearer-header",
			"oidcc-client-test-aggregated-claims",
			"oidcc-client-test-kid-absent-single-jwks",
		])
			loggedIn(test);
	});

	it("takes an id_token signed with RS256 [oidc-core-3.1.3.7-a]", () => {
		loggedIn("oidcc-client-test-idtoken-sig-rs256");
	});

	it("reads the OP's configuration by GET [oidc-discovery-4.1-b]", () => {
		startedOnly("oidcc-client-test-discovery-openid-config");
	});

	it("checks the id_token's signature with the keys the described key set holds [oidc-core-3.1.3.7-j]", () => {
		loggedIn("oidcc-client-test-discovery-jwks-uri-keys");
	});

	it("goes on or stops where the key set holds several keys and the id_token names none", () => {
		// Either is right: the suite ends the test on its own, and the app opens no other user's login.
		expect(outcomeOf("oidcc-client-test-kid-absent-multiple-jwks")).toEqual({ kind: "passed" });
		const side = ran.sides["oidcc-client-test-kid-absent-multiple-jwks"];
		expect([undefined, ran.subject]).toContain(side?.subject);
	});
});

describe("the provider as a relying party, through the suite's OP: refusing", () => {
	it("refuses an id_token whose nonce is not the one sent, using none of its tokens [oidc-core-2-v] [oidc-core-3.1.3.7-k] [rfc9700-4.5.3.2-a]", () => {
		refused("oidcc-client-test-nonce-invalid");
	});

	it("refuses an id_token whose aud does not hold the client [oidc-core-3.1.3.7-e]", () => {
		refused("oidcc-client-test-missing-aud");
		refused("oidcc-client-test-invalid-aud");
	});

	it("refuses an id_token whose signature does not verify under the issuer's keys [oidc-core-3.1.3.7-i] [oidc-core-16.3-a]", () => {
		refused("oidcc-client-test-invalid-sig-rs256");
		refused("oidcc-client-test-invalid-sig-es256");
	});

	it("refuses an id_token signed with a MAC, an algorithm the IdP does not take [oidc-core-3.1.3.7-i]", () => {
		refused("oidcc-client-test-invalid-sig-hs256");
	});

	it("refuses an id_token whose iss is not the issuer's [oidc-core-3.1.3.7-d]", () => {
		refused("oidcc-client-test-invalid-iss");
	});

	it("refuses an id_token without iat or sub", () => {
		refused("oidcc-client-test-missing-iat");
		refused("oidcc-client-test-missing-sub");
	});

	it("refuses a UserInfo answer whose sub is not the id_token's [oidc-core-5.3.2-n]", () => {
		refused("oidcc-client-test-userinfo-invalid-sub");
	});

	it("refuses to start on a configuration naming another issuer [oidc-discovery-4.3-b] [oidc-discovery-4.3-c]", () => {
		refusedToStart("oidcc-client-test-discovery-issuer-mismatch");
	});

	it("holds both the configuration's issuer and the id_token's iss to the issuer it was given [oidc-discovery-7.2-a]", () => {
		refusedToStart("oidcc-client-test-discovery-issuer-mismatch");
		refused("oidcc-client-test-invalid-iss");
	});
});
