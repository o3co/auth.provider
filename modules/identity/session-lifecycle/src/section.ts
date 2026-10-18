import { setting } from "@mod/kernel";
import { z } from "zod";
import { longestLifetimeSeconds } from "./limits.ts";

export const section = z.strictObject({
	lifetime: setting
		.duration("s")
		.pipe(z.number().int().min(60).max(longestLifetimeSeconds))
		.prefault("1h")
		.describe(
			"How long a session lasts, counted from its opening, from 1m to 30d, such as 8h; its cookie lives as long. The lifetime in force decides on each read, so a shorter one ends sessions opened under a longer one.",
		),
	"sweep-interval": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(3600))
		.prefault("30s")
		.describe(
			"How often each host goes on with pending closes, from 1s to 1h, such as 1m; a close whose participants keep failing is retried after half its age, at least this, at most an hour.",
		),
	"credentials-within": setting
		.duration("s")
		.pipe(z.number().int().min(30).max(3600))
		.prefault("5m")
		.describe(
			"Where no entry requirement judges changing credentials (no mfa), how recent a sign-in at a known time must be to do so, from 30s to 1h, such as 10m.",
		),
});
