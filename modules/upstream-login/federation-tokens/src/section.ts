import { setting } from "@mod/kernel";
import { z } from "zod";

/** A time in whole seconds, written with its unit. */
const seconds = (min: number, max: number) =>
	setting.duration("s").pipe(z.number().int().min(min).max(max));

export const section = z.strictObject({
	"refresh-before": seconds(0, 3600)
		.prefault("30s")
		.describe(
			"A token this close to its end is refreshed before it is handed over, from 0s to 1h.",
		),
	"max-lifetime": seconds(60, 31_536_000)
		.prefault("1d")
		.describe(
			"The longest a token is taken to live, from 1m to 365d: caps what an upstream says, and stands for an answer that says nothing.",
		),
	"lock-lifetime": seconds(1, 60)
		.prefault("5s")
		.describe(
			"How long a refresh's lock lasts unless kept, as it is every half of this while the refresh runs, and how long another request waits for it, from 1s to 1m.",
		),
	requests: z
		.number()
		.int()
		.min(1)
		.max(1000)
		.prefault(60)
		.describe("Requests allowed per source in each window."),
	window: seconds(1, 3600)
		.prefault("1m")
		.describe("The window `requests` counts in, from 1s to 1h."),
});
