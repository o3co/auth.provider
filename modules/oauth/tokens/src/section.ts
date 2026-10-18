import { setting } from "@mod/kernel";
import { z } from "zod";
import { defaultLifetimeSeconds } from "./limits.ts";

const lifetime = z.number().int().min(1).max(86_400);

export const section = z
	.strictObject({
		"access-token-lifetime": setting
			.duration("s")
			.pipe(lifetime)
			.optional()
			.describe(
				"How long an access token lives, from `1s` to `1d` in whole seconds; `1h` unless set.",
			),
		// Read until every writer names access-token-lifetime, then removed.
		"access-token-lifetime-seconds": lifetime
			.optional()
			.describe("Replaced by `access-token-lifetime`; read until 0.18.0."),
		revocation: z
			.enum(["denylist", "unsupported"])
			.describe(
				"Whether revoked access tokens are kept in a denylist and refused, or revocation is not supported.",
			),
		"subject-check": z
			.literal("none")
			.optional()
			.describe("Stated where no module checks subject revocation on access tokens."),
	})
	.refine(
		(s) =>
			s["access-token-lifetime"] === undefined || s["access-token-lifetime-seconds"] === undefined,
		{ message: "access-token-lifetime replaces access-token-lifetime-seconds: write one" },
	)
	.transform(({ "access-token-lifetime-seconds": old, ...s }) => ({
		...s,
		"access-token-lifetime": s["access-token-lifetime"] ?? old ?? defaultLifetimeSeconds,
	}));
