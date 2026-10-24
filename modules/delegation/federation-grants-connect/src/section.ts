import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export const name = "federation-grants-connect";

const page = urlSetting({ schemes: ["https"], loopbackHttp: true });

export const section = z.strictObject({
	page: page
		.optional()
		.describe(
			"The page that asks the user; it posts the decision under `csrf`, so serve it on this deployment's origin (not checked at boot): an https URL (http only on a loopback host). Connections refuse boot without it.",
		),
	"login-page": page
		.optional()
		.describe(
			"Where a browser with no session is sent to log in, then back: an https URL (http only on a loopback host).",
		),
	"step-up-page": page
		.optional()
		.describe(
			"Where a session that falls short of a requirement is sent once to raise it, then back: an https URL (http only on a loopback host).",
		),
	"identity-check": z
		.enum(["required", "none"])
		.prefault("required")
		.describe(
			"required refuses a callback whose upstream account another user holds; none does not check.",
		),
});

export type Settings = z.output<typeof section>;
