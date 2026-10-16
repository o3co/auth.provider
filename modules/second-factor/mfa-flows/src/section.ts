import { z } from "zod";

export const section = z.strictObject({
	"transaction-seconds": z.number().int().min(60).max(1800).default(600),
	"attempts-per-transaction": z.number().int().min(2).max(10).default(5),
	/** Requests allowed per source in each window, over every form the flows take. */
	requests: z.number().int().min(1).max(100_000).default(60),
	"window-seconds": z.number().int().min(1).max(86_400).default(300),
	lockout: z
		.strictObject({
			threshold: z.number().int().default(5),
			"backoff-seconds": z.number().int().default(900),
			"max-backoff-seconds": z.number().int().default(86_400),
			budget: z.number().int().default(10),
			"budget-window-seconds": z.number().int().default(604_800),
			"hard-limit": z.number().int().default(100),
			"memory-seconds": z.number().int().default(86_400),
		})
		.prefault({}),
});

export type Settings = z.output<typeof section>;

/** The lockout the proof step keeps under each subject in `rate-limit`. */
export const lockoutName = "mfa";
