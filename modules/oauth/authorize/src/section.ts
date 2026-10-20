import { setting } from "@mod/kernel";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

const page = urlSetting({ schemes: ["https"], loopbackHttp: true });

export const section = z.strictObject({
	"login-page": page.describe(
		"The login page, given the return URL as `redirect_to`, and the `prompt=login` and `max_age` a request asked: an https URL (http only on a loopback host).",
	),
	"step-up-page": page
		.optional()
		.describe(
			"Where a session that falls short of an acr is sent to raise its authentication: an https URL (http only on a loopback host).",
		),
	/** Whether every request names `openid` in its own scope (`dual` also serves plain OAuth clients). */
	"oidc-mode": z
		.enum(["oidc-required", "dual"])
		.prefault("oidc-required")
		.describe(
			"oidc-required refuses a request whose own scope does not name openid, as invalid_scope; dual lets it through with the scope it asks or the client's default.",
		),
	requests: z
		.number()
		.int()
		.min(1)
		.max(100_000)
		.prefault(60)
		.describe(
			"Requests allowed per source in each window, over both methods together; over it, 429.",
		),
	window: setting
		.duration("s")
		.pipe(z.number().int().min(1).max(86_400))
		.prefault("1m")
		.describe("The rate limit's window: a duration with a unit, e.g. 1m."),
});

export type Settings = z.output<typeof section>;
