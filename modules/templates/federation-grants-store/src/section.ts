import { z } from "zod";

/** How many first-time intents a client may have waiting for one subject, and how many grants a subject's listing keeps; the card says why the defaults. */
export const section = z.strictObject({
	"pending-per-client-and-subject": z
		.number()
		.int()
		.min(1)
		.max(1000)
		.default(16)
		.describe(
			"How many first-time intents a client may have waiting for one subject; past it, the one ending first is pushed out.",
		),
	"grants-per-subject": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.default(100)
		.describe(
			"How many grants a subject's listing keeps; past it, the one ending first is pushed out.",
		),
});
