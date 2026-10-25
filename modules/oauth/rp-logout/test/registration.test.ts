import { BootRefused } from "@mod/kernel";
import { expect, it } from "vitest";
import { back, harness } from "./harness.ts";

it("refuses at boot a registered client whose back channel outbound's destination policy refuses", async () => {
	const sections = {
		app: {
			"post-logout-redirect-uris": [back],
			"backchannel-logout-uri": "https://app.example/bc",
		},
		far: { "backchannel-logout-uri": "https://far.example/bc" },
	};
	const refused = (url: string) =>
		url.startsWith("https://far.example")
			? "not an allowed host: list it in outbound.allow"
			: undefined;
	const answer = await harness({ sections, refused }).catch((error: unknown) => error);
	expect(BootRefused.is(answer)).toBe(true);
	const refusals = (answer as BootRefused).refusals;
	expect(refusals).toHaveLength(1);
	expect(refusals[0]?.reason).toBe(
		"outbound's destination policy refuses the backchannel-logout-uri: not an allowed host: list it in outbound.allow",
	);
	expect(JSON.stringify(refusals)).not.toContain("far.example");
	await expect(harness({ sections })).resolves.toBeDefined();
});
