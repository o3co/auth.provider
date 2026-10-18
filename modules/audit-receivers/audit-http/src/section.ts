import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

/** How the fragment's sample of a secret begins: never a value to send. */
const placeholder = "REPLACE-";

export const section = z.strictObject({
	url: urlSetting({ schemes: ["https", "http"] }).describe(
		"Where each event is posted; outbound's destination policy decides whether it is reached.",
	),
	authorization: z
		.string()
		.regex(
			/^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/,
			"printable ASCII on one line, no space at either end",
		)
		.refine((value) => !value.startsWith(placeholder), "the fragment's placeholder, not a value")
		.optional()
		.describe(
			"The Authorization header's whole value the collector asks for; a secret, never logged.",
		),
});
