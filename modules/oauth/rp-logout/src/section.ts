import { z } from "zod";

export const section = z.strictObject({
	/** How long a session's clients are kept from a redemption; at least as long as a session lives. */
	"remember-seconds": z.number().int().min(60).max(2_592_000).default(86_400),
	/** How long an undelivered back-channel notice is tried again. */
	"notify-seconds": z.number().int().min(60).max(604_800).default(86_400),
	"sweep-seconds": z.number().int().min(1).max(3600).default(60),
});

export type Settings = z.output<typeof section>;
