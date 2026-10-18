import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	requests: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.prefault(60)
		.describe("Requests allowed per source in each window, over every POST the routes take."),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("5m")
		.describe(
			"The window `requests` is counted over, from 1s to 1d in whole seconds, such as `5m`.",
		),
});

export type Settings = z.output<typeof section>;
