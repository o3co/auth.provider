import { setting } from "@mod/kernel";
import { z } from "zod";
import { longestLifetimeSeconds } from "./limits.ts";

/** A key named before its unit was written: read in place of its new name while its writers move. */
const before = (min: number, max: number, instead: string) =>
	z
		.number()
		.int()
		.min(min)
		.max(max)
		.optional()
		.describe(`Deprecated: seconds, as a bare number; write \`${instead}\` with its unit instead.`);

const keys = z.strictObject({
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
	"lifetime-seconds": before(60, longestLifetimeSeconds, "lifetime"),
	"sweep-seconds": before(1, 3600, "sweep-interval"),
	"credentials-seconds": before(30, 3600, "credentials-within"),
});

/** Each name in seconds, and the name without a unit that replaces it. */
const renamed = {
	"lifetime-seconds": "lifetime",
	"sweep-seconds": "sweep-interval",
	"credentials-seconds": "credentials-within",
} as const;

/** Refuses a key given under both its names: the value in seconds would silently win or lose. */
const oneNameEach = (raw: z.input<typeof keys>, context: z.RefinementCtx) => {
	if (typeof raw !== "object" || raw === null) return raw;
	for (const [old, now] of Object.entries(renamed)) {
		if (Object.hasOwn(raw, old) && Object.hasOwn(raw, now)) {
			context.addIssue({
				code: "custom",
				path: [old],
				message: `names ${now} again, in seconds; write ${now} alone`,
				input: raw,
			});
		}
	}
	return raw;
};

export const section = z.preprocess(
	oneNameEach,
	keys.transform(
		({
			"lifetime-seconds": lifetimeSeconds,
			"sweep-seconds": sweepSeconds,
			"credentials-seconds": credentialsSeconds,
			...read
		}) => ({
			lifetime: lifetimeSeconds ?? read.lifetime,
			"sweep-interval": sweepSeconds ?? read["sweep-interval"],
			"credentials-within": credentialsSeconds ?? read["credentials-within"],
		}),
	),
);
