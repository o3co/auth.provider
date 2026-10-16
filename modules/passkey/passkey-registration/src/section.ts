import { z } from "zod";

export const section = z.strictObject({
	requests: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.default(60)
		.describe("Requests allowed per source in each window, over both registration routes."),
	"window-seconds": z
		.number()
		.int()
		.min(1)
		.max(86_400)
		.default(300)
		.describe("The window, in seconds, that requests are counted over."),
});

export type Settings = z.output<typeof section>;
