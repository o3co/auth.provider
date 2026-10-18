import { z } from "zod";

/** How the list of codes to void is spread; the card says why the defaults. */
export const section = z.strictObject({
	"void-shards": z
		.number()
		.int()
		.min(1)
		.max(65_536)
		.prefault(1024)
		.describe("How many shards the list of codes to revoke is spread over."),
	"voids-per-shard": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.prefault(1000)
		.describe("How many codes to revoke one shard holds at most."),
});
