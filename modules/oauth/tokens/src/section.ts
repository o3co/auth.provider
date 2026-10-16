import { z } from "zod";
import { defaultLifetimeSeconds } from "./limits.ts";

export const section = z.strictObject({
	"access-token-lifetime-seconds": z
		.number()
		.int()
		.min(1)
		.max(86_400)
		.default(defaultLifetimeSeconds)
		.describe("How long an access token lives, in seconds."),
	revocation: z
		.enum(["denylist", "unsupported"])
		.describe(
			"Whether revoked access tokens are kept in a denylist and refused, or revocation is not supported.",
		),
	"subject-check": z
		.literal("none")
		.optional()
		.describe("Stated where no module checks subject revocation on access tokens."),
});
