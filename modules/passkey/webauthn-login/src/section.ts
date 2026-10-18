import { setting } from "@mod/kernel";
import { z } from "zod";

const seconds = z.number().int().min(1).max(86_400);

const window = setting
	.duration("s")
	.pipe(seconds)
	.prefault("1m")
	.describe(
		"The window `requests` is counted over, from 1s to 1d in whole seconds, written with its unit, such as `1m`.",
	);

/**
 * The window under its new name, left absent when not given, so its name in seconds can be read in
 * its place; its prefault still states the default. (An optional prefault fills absence; the
 * preprocess between them keeps it.)
 */
const kept = z.preprocess((value) => value, window).optional();

export const section = z
	.strictObject({
		/** Requests allowed per source in each window, on the options route. */
		requests: z.number().int().min(1).max(100_000).prefault(60),
		window: kept,
		"window-seconds": seconds
			.optional()
			.describe("Seconds, read in place of `window`, which replaces it; giving both refuses boot."),
	})
	.superRefine((s, ctx) => {
		// Which of the two the operator meant cannot be told.
		if (s.window !== undefined && s["window-seconds"] !== undefined) {
			ctx.addIssue({
				code: "custom",
				message: "window replaces window-seconds: write one",
				path: ["window-seconds"],
			});
		}
	})
	.transform(({ "window-seconds": old, ...s }) => ({
		...s,
		window: s.window ?? old ?? window.parse(undefined),
	}));

export type Settings = z.output<typeof section>;
