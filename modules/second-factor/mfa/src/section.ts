import { setting } from "@mod/kernel";
import { z } from "zod";
import { longestRecentMs } from "./contract.ts";

const manage = z
	.number()
	.int()
	.min(30)
	.max(longestRecentMs / 1000);
/** How recent a proof must be to change credentials where the section names neither key, in seconds. */
const manageDefault = 300;

export const section = z
	.strictObject({
		mode: z
			.enum(["optional", "required"])
			.prefault("required")
			.describe(
				'"required" (the default) asks every login for a counting factor; "optional" only of those who hold one.',
			),
		"manage-within": setting
			.duration("s")
			.pipe(manage)
			.optional()
			.describe(
				"How recently a second factor must have been proved to change credentials, from `30s` to `1h` in whole seconds; `5m` unless set.",
			),
		// Read until every writer names manage-within, then removed.
		"manage-seconds": manage.optional().describe("Replaced by `manage-within`; read until 0.18.0."),
		"max-factors": z
			.number()
			.int()
			.min(2)
			.max(50)
			.prefault(10)
			.describe("How many factors a subject may hold, recovery codes included."),
	})
	.refine((s) => s["manage-within"] === undefined || s["manage-seconds"] === undefined, {
		message: "manage-within replaces manage-seconds: write one",
	})
	.transform(({ "manage-seconds": old, ...s }) => ({
		...s,
		"manage-within": s["manage-within"] ?? old ?? manageDefault,
	}));

export type Settings = z.output<typeof section>;
