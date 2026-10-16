import { z } from "zod";

export const section = z.strictObject({
	/** Requests allowed per source in each window, before any client is authenticated. */
	requests: z.number().int().min(1).max(100_000).default(60),
	"window-seconds": z.number().int().min(1).max(86_400).default(60),
});
