import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export const section = z.strictObject({
	"verification-uri": urlSetting({ schemes: ["https"] }).describe(
		"The deployment's page where a user enters the code.",
	),
	"complete-uri": z
		.boolean()
		.default(false)
		.describe("Whether to answer also the page's address with the code filled in."),
	"code-seconds": z
		.number()
		.int()
		.min(30)
		.max(3600)
		.default(600)
		.describe("How long a device code and its user code live, in seconds."),
	"interval-seconds": z
		.number()
		.int()
		.min(1)
		.max(60)
		.default(5)
		.describe("How long a device waits between polls of the token endpoint, in seconds."),
	attempts: z
		.number()
		.int()
		.min(1)
		.max(100)
		.default(5)
		.describe("Decisions a subject may try in each window, so codes cannot be guessed."),
	"attempts-window-seconds": z
		.number()
		.int()
		.min(60)
		.max(86_400)
		.default(300)
		.describe("The window `attempts` is counted over, in seconds."),
	requests: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.default(60)
		.describe("Device authorization requests per source in each window."),
	"window-seconds": z
		.number()
		.int()
		.min(1)
		.max(86_400)
		.default(60)
		.describe("The window `requests` is counted over, in seconds."),
});

export type Settings = z.output<typeof section>;
