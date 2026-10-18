import { setting } from "@mod/kernel";
import { z } from "zod";

/** A key named before its unit was written: read in place of its new name while its writers move. */
const before = (min: number, max: number, instead: string) =>
	z.number().int().min(min).max(max).optional().describe(`Seconds; write \`${instead}\` instead.`);

export const section = z.strictObject({
	"code-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(10).max(600))
		.prefault("10m")
		.describe("How long a code can be redeemed, from 10s to 10m."),
	"sweep-interval": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(3600))
		.prefault("30s")
		.describe(
			"How often each host retries the revocations a code that came again left, from 1s to 1h.",
		),
	"code-seconds": before(10, 600, "code-lifetime"),
	"sweep-seconds": before(1, 3600, "sweep-interval"),
});
