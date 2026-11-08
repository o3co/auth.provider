import { addedClaimsLimits } from "@mod/added-claims";
import { setting } from "@mod/kernel";
import { z } from "zod";
import { lifetimeSecondsRange } from "./contract.ts";

export const section = z.strictObject({
	"access-token-lifetime": setting
		.duration("s")
		// A second's lifetime, its iat cut to the second, leaves less than a second once signed: never issued.
		.pipe(z.number().int().min(lifetimeSecondsRange.min).max(lifetimeSecondsRange.max))
		.prefault("1h")
		.describe(
			"How long an access token lives, from when it is asked for (the issuance policies' wait included), from `2s` to `1d` in whole seconds.",
		),
	revocation: z
		.enum(["denylist", "unsupported"])
		.describe(
			"Whether revoked access tokens are kept in a denylist and refused, or revocation is not supported.",
		),
	"issuance-timeout": setting
		.duration("ms")
		.pipe(z.number().int().min(1000).max(60_000))
		.prefault("10s")
		.describe(
			"How long the issuance policies may take together, from `1s` to `1m`; past it, the issuance is unavailable.",
		),
	"subject-check": z
		.literal("none")
		.optional()
		.describe("Stated where no module checks subject revocation on access tokens."),
	"added-claims": addedClaimsLimits.describe(
		"The limits of the claims a grant adds to an access token, as added-claims reads them, each raised only: one value holds both issuing and reading back, so lowering a raised one leaves the tokens issued while it was raised unreadable until they expire.",
	),
});
