import { z } from "zod";
import { longestRecentMs } from "./contract.ts";

export const section = z.strictObject({
	mode: z
		.enum(["optional", "required"])
		.default("required")
		.describe(
			'"required" (the default) asks every login for a counting factor; "optional" only of those who hold one.',
		),
	"manage-seconds": z
		.number()
		.int()
		.min(30)
		.max(longestRecentMs / 1000)
		.default(300)
		.describe(
			"How recently a second factor must have been proved to change credentials, in seconds.",
		),
	"max-factors": z
		.number()
		.int()
		.min(2)
		.max(50)
		.default(10)
		.describe("How many factors a subject may hold, recovery codes included."),
});

export type Settings = z.output<typeof section>;
