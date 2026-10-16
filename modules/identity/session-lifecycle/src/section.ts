import { sessionRules } from "@mod/session";
import { z } from "zod";
import { defaultLifetimeSeconds, longestLifetimeSeconds } from "./limits.ts";

export const section = z.strictObject({
	"lifetime-seconds": z
		.number()
		.int()
		.min(60)
		.max(longestLifetimeSeconds)
		.default(defaultLifetimeSeconds)
		.describe(
			"How long a session lasts, counted from its opening; its cookie lives as long. The lifetime in force decides on each read, so a shorter one ends sessions opened under a longer one.",
		),
	"sweep-seconds": z
		.number()
		.int()
		.min(1)
		.max(3600)
		.default(30)
		.describe(
			"How often each host goes on with pending closes; a close whose participants keep failing is retried after half its age, at least this, at most an hour.",
		),
	"credentials-seconds": z
		.number()
		.int()
		.min(30)
		.max(3600)
		.default(sessionRules.credentialsSecondsDefault)
		.describe(
			"Where no entry requirement judges changing credentials (no mfa), how recent a sign-in at a known time must be to do so.",
		),
});
