import { z } from "zod";

export const section = z.strictObject({
	/** A token this close to its end is refreshed before it is handed over. */
	"refresh-before-seconds": z.number().int().min(0).max(3600).default(30),
	/** The longest a token is taken to live: caps what an upstream says, and stands for an answer that says nothing. */
	"max-lifetime-seconds": z.number().int().min(60).max(31_536_000).default(86_400),
	/** How long one refresh holds its lock, and how long another request waits for it. */
	"lock-seconds": z.number().int().min(1).max(60).default(5),
	/** Requests allowed per source in each window. */
	requests: z.number().int().min(1).max(1000).default(60),
	"window-seconds": z.number().int().min(1).max(3600).default(60),
});
