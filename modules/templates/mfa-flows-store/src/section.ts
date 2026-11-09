import { z } from "zod";

/** How many live transactions a holder's listing keeps. */
export const section = z.strictObject({
	"transactions-per-holder": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.prefault(5)
		.describe(
			"How many live MFA transactions a holder's listing keeps, from 1 to 10000; past it, the one ending first is pushed out.",
		),
});
