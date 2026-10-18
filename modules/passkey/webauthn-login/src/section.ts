import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	/** Requests allowed per source in each window, on the options route. */
	requests: z.number().int().min(1).max(100_000).prefault(60),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("1m")
		.describe(
			"The window `requests` is counted over, from 1s to 1d in whole seconds, written with its unit, such as `1m`.",
		),
});

export type Settings = z.output<typeof section>;
