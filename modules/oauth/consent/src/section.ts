import { setting } from "@mod/kernel";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export const section = z.strictObject({
	page: urlSetting({ schemes: ["https"], loopbackHttp: true })
		.optional()
		.describe(
			"The deployment's consent page, with the challenge as its `challenge` query parameter; without it, nobody is asked, and only first-party clients are served. An https URL (http only on a loopback host, with `kernel.environment = development`, as authorize's login page).",
		),
	"challenge-lifetime": setting
		.duration("s")
		.pipe(z.number().int().min(60).max(3600))
		.prefault("10m")
		.describe(
			"How long a pending consent challenge stays answerable, from `1m` to `1h` in whole seconds.",
		),
});
