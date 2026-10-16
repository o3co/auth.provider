import { z } from "zod";

export const section = z.strictObject({
	requests: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.default(60)
		.describe(
			"Requests allowed per source in each window, on each route, before any client is authenticated.",
		),
	"window-seconds": z
		.number()
		.int()
		.min(1)
		.max(86_400)
		.default(60)
		.describe("The window `requests` is counted over, in seconds."),
});
