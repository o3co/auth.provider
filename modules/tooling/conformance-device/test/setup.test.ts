import { expect, it } from "vitest";
import { setUp } from "../src/new.ts";

it("composes, with device-grant, what records its tokens to the session that approved them", () => {
	const set = setUp({ verificationUri: "https://issuer.example/device" });
	expect(set.modules).toEqual(expect.arrayContaining(["@mod/device-grant", "@mod/session-tokens"]));
});

it("lets the tokens it issues be revoked, as session-tokens asks to start", () => {
	const set = setUp({ verificationUri: "https://issuer.example/device" });
	expect(set.config).toMatchObject({ tokens: { revocation: "denylist" } });
});
