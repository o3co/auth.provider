import { setting } from "@mod/kernel";
import { z } from "zod";

/** What new enrolments' codes are made with, and the window every factor's check takes. */
export const section = z.strictObject({
	algorithm: z
		.enum(["SHA1", "SHA256", "SHA512"])
		.prefault("SHA1")
		.describe(
			"The HMAC new enrolments' codes are made with: SHA1, SHA256 or SHA512. A factor keeps what it was enrolled with; moving it means enrolling again. Some authenticator apps make SHA1 codes whatever the enrolment asks, and the enrolment's first code then fails, so nothing is bound.",
		),
	digits: z
		.number()
		.int()
		.min(6)
		.max(8)
		.prefault(6)
		.describe(
			"How many digits new enrolments' codes have, from 6 to 8. A factor keeps what it was enrolled with; some apps make 6 whatever the enrolment asks.",
		),
	period: setting
		.duration("s")
		.pipe(z.union([z.literal(30), z.literal(60)]))
		.prefault("30s")
		.describe(
			"How long a step of new enrolments' codes lasts: 30s or 60s. A factor keeps what it was enrolled with; some apps step every 30s whatever the enrolment asks.",
		),
	"drift-steps": z
		.number()
		.int()
		.min(0)
		.max(1)
		.prefault(1)
		.describe(
			"How many of a factor's own steps either side of the current one a code is taken for, 0 or 1 (RFC 6238 §5.2 advises no more than one); every factor's check reads it.",
		),
});

export type Settings = z.output<typeof section>;
