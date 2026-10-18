import { z } from "zod";

/** How many references the set keeps to a session, and how the pending sessions are spread; the card says why the defaults. */
export const section = z.strictObject({
	"references-per-session": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.prefault(1000)
		.describe(
			"How many token references a session's set keeps; past it, one is pushed out and its token revoked.",
		),
	"pending-shards": z
		.number()
		.int()
		.min(1)
		.max(65_536)
		.prefault(64)
		.describe("How many shards the sessions pending a push-out are spread over."),
	"pending-per-shard": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.prefault(1000)
		.describe("How many pending sessions one shard holds; an add to a full shard is refused."),
});
