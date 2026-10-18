import { setting } from "@mod/kernel";
import { z } from "zod";

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
		.pipe(z.number().int().min(0).max(300))
		.prefault("30s")
		.describe(
			"How far a client's clock may be off when an assertion's times are checked, from `0s` to `5m` in whole seconds.",
		),
});
