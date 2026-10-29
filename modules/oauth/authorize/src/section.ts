import { setting } from "@mod/kernel";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

const page = urlSetting({ schemes: ["https"], loopbackHttp: true });

export const section = z.strictObject({
	"login-page": page.describe(
		"The login page, given the return URL as `redirect_to`, and the `prompt=login` and `max_age` a request asked: an https URL (http only on a loopback host, with `kernel.environment = development`).",
	),
	"step-up-page": page
		.optional()
		.describe(
			"Where a session that falls short of an acr is sent to raise its authentication: an https URL (http only on a loopback host, with `kernel.environment = development`).",
		),
	/** Whether every request names `openid` in its own scope (`dual` also serves plain OAuth clients). */
	"oidc-mode": z
		.enum(["oidc-required", "dual"])
		.prefault("oidc-required")
		.describe(
			"oidc-required refuses a request whose own scope does not name openid, as invalid_scope; dual lets it through with the scope it asks or the client's default.",
		),
	"claims-parameter": z
		.boolean()
		.prefault(true)
		.describe(
			"Whether the claims request parameter's names and value constraints are taken, and discovery says it is supported. False ignores them, and boot warns; the sub asked, the acr, an essential auth_time and the parameter's form still hold, as do the scope's claims and the selections already kept.",
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
