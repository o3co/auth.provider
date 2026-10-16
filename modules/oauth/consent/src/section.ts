import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export const section = z.strictObject({
	page: urlSetting({ schemes: ["https"] })
		.optional()
		.describe(
			"The deployment's consent page, with the challenge as its `challenge` query parameter; without it, nobody is asked.",
		),
	"challenge-seconds": z
		.number()
		.int()
		.min(60)
		.max(3600)
		.default(600)
		.describe("How long a pending consent challenge stays answerable, in seconds."),
});
