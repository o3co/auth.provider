import { expect, it } from "vitest";
import { section } from "../src/section.ts";

it("sends on port 587 by STARTTLS within 40s, 20 at once, where nothing else is set", () => {
	expect(section.parse({ host: "relay.example", from: "noreply@example.test" })).toMatchObject({
		port: 587,
		security: "starttls",
		deadline: 40_000,
		"concurrent-sends": 20,
	});
});
