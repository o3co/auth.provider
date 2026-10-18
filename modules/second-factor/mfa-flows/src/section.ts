import { setting } from "@mod/kernel";
import { z } from "zod";

/** A time written with its unit, read in whole seconds. */
const seconds = () => setting.duration("s").pipe(z.number().int());

export const section = z.strictObject({
	"transaction-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(60).max(1800))
		.prefault("10m")
		.describe(
			"How long a transaction waits for its factor, from 1m to 30m in whole seconds, such as `10m`.",
		),
	"attempts-per-transaction": z.number().int().min(2).max(10).prefault(5),
	/** Requests allowed per source in each window, over every form the flows take. */
	requests: z.number().int().min(1).max(100_000).prefault(60),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("5m")
		.describe(
			"The window `requests` is counted over, from 1s to 1d in whole seconds, such as `5m`.",
		),
	lockout: z
		.strictObject({
			threshold: z.number().int().prefault(5),
			backoff: seconds()
				.prefault("15m")
				.describe("The first hold after `threshold` failures, in whole seconds, such as `15m`."),
			"max-backoff": seconds()
				.prefault("1d")
				.describe("The longest hold, the first doubling up to it, in whole seconds, such as `1d`."),
			budget: z.number().int().prefault(10),
			"budget-window": seconds()
				.prefault("7d")
				.describe("The window `budget` is counted over, in whole seconds, such as `7d`."),
			"hard-limit": z.number().int().prefault(100),
			memory: seconds()
				.prefault("1d")
				.describe(
					"How long a run of failures is remembered without one, in whole seconds, such as `1d`.",
				),
		})
		.prefault({}),
});

export type Settings = z.output<typeof section>;

/** The lockout the proof step keeps under each subject in `rate-limit`. */
export const lockoutName = "mfa";
