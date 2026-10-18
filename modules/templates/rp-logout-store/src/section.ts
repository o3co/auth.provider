import { z } from "zod";

/** How many clients the set keeps to a session, and how the pending notices are spread; the card says why the defaults. */
export const section = z.strictObject({
	"clients-per-session": z
		.number()
		.int()
		.min(1)
		.max(1000)
		.prefault(64)
		.describe("How many clients a session's set keeps; past it, one is pushed out and logged."),
	"notice-shards": z
		.number()
		.int()
		.min(1)
		.max(65_536)
		.prefault(64)
		.describe("How many shards the logout notices not yet delivered are spread over."),
	"notices-per-shard": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.prefault(1000)
		.describe("How many undelivered notices one shard holds; an add to a full shard is refused."),
});
