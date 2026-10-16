import { z } from "zod";

/** How many members each list keeps to a key, and how the settle list is spread; the card says why the defaults. */
export const section = z.strictObject({
	"families-per-session": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.default(1000)
		.describe(
			"How many refresh token families a session's set keeps; past it, one is pushed out and revoked.",
		),
	"tokens-per-family": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.default(1000)
		.describe(
			"How many access tokens a family's set keeps; past it, one is pushed out and revoked.",
		),
	"settle-shards": z
		.number()
		.int()
		.min(1)
		.max(65_536)
		.default(1024)
		.describe("How many shards the list of families to settle is spread over."),
	"settles-per-shard": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.default(1000)
		.describe("How many families to settle one shard holds at most."),
});
