import { describe, expect, it } from "vitest";
import type { FederationPart } from "../src/area.ts";
import { onPattern } from "../src/new.ts";

const part: FederationPart = {
	origin: "https://as.example",
	idps: [{ name: "corp", issuer: "http://127.0.0.1:1", clientId: "c", clientSecret: "s" }],
	landing: "https://app.example/",
	returnTargets: [],
};

describe("the federation part on a pattern's app", () => {
	it("leaves a scene linking from the deployment out where a ledger holds the links, and sets up any other as on the new system", () => {
		const ledgered = ["@mod/users-http", "@mod/federation"];
		expect(onPattern({ ...part, links: true }, { parts: {} }, ledgered)).toEqual({
			leaveOut:
				"links from the deployment: a ledger looking users up by upstream identity holds the links, so a link answers already or conflict",
		});
		expect(onPattern(part, { parts: {} }, ledgered)).toHaveProperty("modules");
		expect(onPattern({ ...part, links: true }, { parts: {} }, ["@mod/federation"])).toHaveProperty(
			"modules",
		);
	});
});
