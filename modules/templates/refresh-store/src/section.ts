import { z } from "zod";

/** How many members each list keeps to a key, and how the settle list is spread: deprecated, as nothing reads them now. */
export const section = z.strictObject({
	"families-per-session": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.prefault(1000)
		.describe(
			"Deprecated: `refresh` no longer reads or writes this set, so it has no effect; a later release refuses it. How many refresh token families a session's set keeps.",
		),
	"tokens-per-family": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.prefault(1000)
		.describe(
			"Deprecated: `refresh` no longer reads or writes this set, so it has no effect; a later release refuses it. How many access tokens a family's set keeps.",
		),
	"settle-shards": z
		.number()
		.int()
		.min(1)
		.max(65_536)
		.prefault(1024)
		.describe(
			"Deprecated: `refresh` no longer reads or writes this list, so it has no effect; a later release refuses it. How many shards the list of families to settle is spread over.",
		),
	"settles-per-shard": z
		.number()
		.int()
		.min(1)
		.max(10_000)
		.prefault(1000)
		.describe(
			"Deprecated: `refresh` no longer reads or writes this list, so it has no effect; a later release refuses it. How many families to settle one shard holds at most.",
		),
});
