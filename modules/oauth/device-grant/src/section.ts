import { setting } from "@mod/kernel";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export const section = z.strictObject({
	"verification-uri": urlSetting({ schemes: ["https"] }).describe(
		"The deployment's page where a user enters the code.",
	),
	"complete-uri": z
		.boolean()
		.prefault(false)
		.describe("Whether to answer also the page's address with the code filled in."),
	"code-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(30).max(3600))
		.prefault("10m")
		.describe(
			"How long a device code and its user code live, from `30s` to `1h` in whole seconds.",
		),
	interval: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(60))
		.prefault("5s")
		.describe(
			"How long a device waits between polls of the token endpoint, from `1s` to `1m` in whole seconds.",
		),
	attempts: z
		.number()
		.int()
		.min(1)
		.max(100)
		.prefault(5)
		.describe("Decisions a subject may try in each window, so codes cannot be guessed."),
	"attempts-window": setting
		.duration("s")
		.pipe(z.number().int().min(60).max(86_400))
		.prefault("5m")
		.describe("The window `attempts` is counted over, from `1m` to `1d` in whole seconds."),
	requests: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.prefault(60)
		.describe("Device authorization requests per source in each window."),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("1m")
		.describe("The window `requests` is counted over, from `1s` to `1d` in whole seconds."),
});

export type Settings = z.output<typeof section>;
