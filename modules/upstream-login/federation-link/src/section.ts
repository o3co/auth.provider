import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export const name = "federation-link";

/** A configured page: https, or http on a loopback host. */
const page = urlSetting({ schemes: ["https"], loopbackHttp: true });

export const section = z.strictObject({
	"step-up-page": page
		.optional()
		.describe(
			"Where a link's start that falls short of a session requirement sends the browser once to raise it, then back to the start: an https URL (http only on a loopback host, with `kernel.environment = development`). Without it, the start's 403 names no page. A login at an upstream IdP comes back to a page the browser loads on the public origin, written in `login-gates.return-targets`, which then navigates to the start: a landing on the start, or redirected there, comes from the IdP's site and is refused.",
		),
});

export type Settings = z.output<typeof section>;
