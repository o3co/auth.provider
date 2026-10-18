import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	requests: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.prefault(60)
		.describe(
			"Requests allowed per source in each window, on the options route, from 1 to 100000.",
		),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("1m")
		.describe(
			"The window `requests` is counted over, from 1s to 1d in whole seconds, written with its unit, such as `1m`.",
		),
});

export type Settings = z.output<typeof section>;
