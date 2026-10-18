import { setting } from "@mod/kernel";
import { z } from "zod";
import { longestRecentMs } from "./contract.ts";

export const section = z.strictObject({
	mode: z
		.enum(["optional", "required"])
		.prefault("required")
		.describe(
			'"required" (the default) asks every login for a counting factor; "optional" only of those who hold one.',
		),
	"manage-within": setting
		.duration("s")
		.pipe(
			z
				.number()
				.int()
				.min(30)
				.max(longestRecentMs / 1000),
		)
		.prefault("5m")
		.describe(
			"How recently a second factor must have been proved to change credentials, from `30s` to `1h` in whole seconds.",
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
