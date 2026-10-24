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
		.optional()
		.describe(
			"required refuses a callback whose upstream account another user holds; none does not check. Unset, for now the one federation-grants' section holds (required unless set).",
		),
});

export type Section = z.output<typeof section>;

/** The browser half's settings: its own, else, for now, those federation-grants' section still holds (TODO 96). */
export interface Settings {
	readonly page?: string;
	readonly "login-page"?: string;
	readonly "step-up-page"?: string;
	readonly "identity-check": "required" | "none";
}

export const settingsOf = (
	own: Section,
	legacy: {
		readonly page?: string;
		readonly loginPage?: string;
		readonly stepUpPage?: string;
		readonly identityCheck: "required" | "none";
	},
): Settings => {
	const page = own.page ?? legacy.page;
	const login = own["login-page"] ?? legacy.loginPage;
	const stepUp = own["step-up-page"] ?? legacy.stepUpPage;
	return {
		...(page === undefined ? {} : { page }),
		...(login === undefined ? {} : { "login-page": login }),
		...(stepUp === undefined ? {} : { "step-up-page": stepUp }),
		"identity-check": own["identity-check"] ?? legacy.identityCheck,
	};
};
