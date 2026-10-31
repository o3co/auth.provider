import { setting } from "@mod/kernel";
import { z } from "zod";

/** A time written with its unit, read in whole seconds. */
const seconds = () => setting.duration("s").pipe(z.number().int());

/** NIST SP 800-63B rev 4 §3.2.2: no more than 100 consecutive failed attempts on one authenticator. */
const lockoutCountMax = 100;
/** The shortest a run of failures is remembered, so the failures counted stay consecutive. */
const memoryMin = 3600;

export const section = z.strictObject({
	"transaction-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(60).max(1800))
		.prefault("10m")
		.describe(
			"How long a transaction waits for its factor, from 1m to 30m in whole seconds, such as `10m`.",
		),
	"attempts-per-transaction": z
		.number()
		.int()
		.min(2)
		.max(10)
		.prefault(5)
		.describe(
			"How many proofs one transaction takes, from 2 to 10; the one that uses up the last ends it.",
		),
	requests: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.prefault(60)
		.describe(
			"POSTs allowed per source in each window, over every form this package's routes take, from 1 to 100000.",
		),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("5m")
		.describe(
			"The window `requests` is counted over, from 1s to 1d in whole seconds, such as `5m`.",
		),
	lockout: z
		.strictObject({
			threshold: z
				.number()
				.int()
				.min(1)
				.max(lockoutCountMax)
				.prefault(5)
				.describe(
					"Consecutive failures before the first hold; a positive integer up to 100, no more than `budget`.",
				),
			backoff: seconds()
				.prefault("15m")
				.describe("The first hold after `threshold` failures, in whole seconds, such as `15m`."),
			"max-backoff": seconds()
				.prefault("1d")
				.describe(
					"The longest hold, the first doubling up to it, no shorter than `backoff`, in whole seconds, such as `1d`.",
				),
			budget: z
				.number()
				.int()
				.min(1)
				.max(lockoutCountMax)
				.prefault(10)
				.describe(
					"Failures allowed in any `budget-window`; a positive integer up to 100, from `threshold` to `hard-limit`.",
				),
			"budget-window": seconds()
				.prefault("7d")
				.describe("The window `budget` is counted over, in whole seconds, such as `7d`."),
			"hard-limit": z
				.number()
				.int()
				.min(1)
				.max(lockoutCountMax)
				.prefault(100)
				.describe(
					"Failures in one run after which the hold is fixed until released; a positive integer up to 100, no less than `budget`.",
				),
			memory: setting
				.duration("s")
				.pipe(z.number().int().min(memoryMin))
				.prefault("1d")
				.describe(
					"How long a run of failures is remembered without one, at least 1h and no shorter than `max-backoff`, in whole seconds, such as `1d`.",
				),
		})
		.prefault({}),
});

export type Settings = z.output<typeof section>;

/** The lockout the proof step keeps under each subject in `rate-limit`. */
export const lockoutName = "mfa";
