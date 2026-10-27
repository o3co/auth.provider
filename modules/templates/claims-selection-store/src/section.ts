import { z } from "zod";

/** How the constrained families' list is spread; the card says how to size it, and that the shards stay. */
export const section = z.strictObject({
	"constrained-shards": z
		.number()
		.int()
		.min(1)
		.max(65_536)
		.prefault(1024)
		.describe(
			"How many shards the list of families with constrained selections is spread over; never changed while the list holds any.",
		),
	"constrained-per-shard": z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.prefault(1000)
		.describe(
			"How many families one shard holds at most; past it, a family with a constrained selection does not start.",
		),
});
