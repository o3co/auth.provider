import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	"remember-for": setting
		.duration("s")
		.pipe(z.number().int().min(60).max(2_592_000))
		.prefault("1d")
		.describe(
			"How long a session's clients are kept from a redemption, from 1m to 30d; at least as long as a session lives.",
		),
	"notify-within": setting
		.duration("s")
		.pipe(z.number().int().min(60).max(604_800))
		.prefault("1d")
		.describe("How long an undelivered back-channel notice is tried again, from 1m to 7d."),
	"sweep-interval": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(3600))
		.prefault("1m")
		.describe("How often each host sweeps the kept notices, from 1s to 1h."),
});

export type Settings = z.output<typeof section>;
