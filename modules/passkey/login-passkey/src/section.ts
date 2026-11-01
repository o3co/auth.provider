import { setting } from "@mod/kernel";
import { z } from "zod";

export const section = z.strictObject({
	"counts-as-mfa": z
		.boolean()
		.prefault(true)
		.describe(
			"Whether a passkey login whose user was verified proves a second factor too (amr `mfa`).",
		),
	attempts: z
		.number()
		.int()
		.min(1)
		.max(100)
		.prefault(20)
		.describe("Requests allowed per source in each window, on each of the two routes."),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(60).max(86_400))
		.prefault("15m")
		.describe("The window `attempts` is counted over, from 1m to 1d."),
	password: z
		.enum(["allowed", "refused-when-held"])
		.prefault("allowed")
		.describe(
			"`refused-when-held`: a password login of a subject holding a passkey is refused, but in `password-exempt-group`.",
		),
	"password-exempt-group": z
		.string()
		.min(1)
		.max(256)
		.optional()
		.describe("A group of users whose password logins `refused-when-held` lets through."),
});

export type Settings = z.output<typeof section>;
