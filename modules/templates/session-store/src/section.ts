import { z } from "zod";

/** How the list of closings is spread, and how many sessions a subject's listing keeps; the card says why the defaults. */
export const section = z.strictObject({
	"closing-shards": z
		.number()
		.int()
		.min(1)
		.max(65_536)
		.default(1024)
		.describe("How many shards the list of sessions still closing is spread over."),
	"closings-per-shard": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.default(1000)
		.describe("How many sessions still closing one shard holds at most."),
	"sessions-per-subject": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.default(100)
		.describe(
			"How many sessions a subject's listing keeps; past it, the one ending first is pushed out and logged.",
		),
});
