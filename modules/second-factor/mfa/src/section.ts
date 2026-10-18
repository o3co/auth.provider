import { z } from "zod";

export const section = z.strictObject({
	mode: z
		.enum(["optional", "required"])
		.prefault("required")
		.describe(
			'"required" (the default) asks every login for a counting factor; "optional" only of those who hold one.',
		),
	"max-factors": z
		.number()
		.int()
		.min(2)
		.max(50)
		.prefault(10)
		.describe("How many factors a subject may hold, recovery codes included."),
});

export type Settings = z.output<typeof section>;
