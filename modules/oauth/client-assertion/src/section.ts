import { setting } from "@mod/kernel";
import { type VerifyAlgorithm, verifyAlgorithms } from "@mod/keys";
import { z } from "zod";

/** The widest `clock-skew` a section takes, in seconds: a spent assertion is kept past it, whatever is set. */
export const widestClockSkew = 300;

export const section = z.strictObject({
	"max-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("1h")
		.describe(
			"The longest lifetime a client assertion may have, from `1s` to `1d` in whole seconds.",
		),
	"clock-skew": setting
		.duration("s")
		.pipe(z.number().int().min(0).max(widestClockSkew))
		.prefault("30s")
		.describe(
			"How far a client's clock may be off when an assertion's times are checked, from `0s` to `5m` in whole seconds.",
		),
	algorithms: z
		.array(z.enum(verifyAlgorithms as [VerifyAlgorithm, ...VerifyAlgorithm[]]))
		.min(1)
		.prefault(["RS256", "ES256", "ES384", "ES512", "EdDSA"])
		.transform((named) => [...new Set(named)])
		.describe(
			"The algorithms a client's assertion may be signed with: asymmetric ones only, by default one for each kind of key.",
		),
});
