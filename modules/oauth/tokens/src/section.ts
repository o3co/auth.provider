import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	"access-token-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("1h")
		.describe("How long an access token lives, from `1s` to `1d` in whole seconds."),
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
