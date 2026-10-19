import { destinationRefusal, type OutboundRefusals } from "@mod/outbound-policy";
import {
	clientSetting,
	endpointSetting as endpoint,
	scopeSetting as scope,
} from "@mod/upstream-client";
import { urlsChecked } from "@mod/url-setting";
import { z } from "zod";

/** Where the user is read. */
export const userUrl = (api: string) => `${api.replace(/\/$/, "")}/user`;

/** The hosts requests are narrowed to: the token endpoint's and the API's. */
export const hostsOf = (s: { readonly "token-endpoint": string; readonly api: string }) => [
	...new Set([s["token-endpoint"], s.api].map((url) => new URL(url).hostname)),
];

const section = clientSetting.extend({
	scopes: z.array(scope).prefault(["read:user"]).describe("The scopes asked of GitHub at a login."),
	"authorization-endpoint": endpoint
		.prefault("https://github.com/login/oauth/authorize")
		.describe(
			"Where the browser is sent to log in at GitHub; GitHub's own unless named (GitHub Enterprise).",
		),
	"token-endpoint": endpoint
		.prefault("https://github.com/login/oauth/access_token")
		.describe(
			"Where a code is exchanged for a token; GitHub's own unless named (GitHub Enterprise).",
		),
	api: endpoint
		.prefault("https://api.github.com")
		.describe("Where the user is read; GitHub's own unless named (GitHub Enterprise)."),
	issuer: z
		.string()
		.min(1)
		.prefault("https://github.com/login/oauth")
		.describe("The `iss` a callback carries, where it carries one (RFC 9207)."),
});

/** The section; boot is refused on a URL it sends to that outbound's destination policy refuses. */
export const settingsOf = (refusals: OutboundRefusals) =>
	section.superRefine(
		urlsChecked((url, hosts) => destinationRefusal(refusals, url, { hosts }), {
			urls: (s) => [s["token-endpoint"], s.api],
			sent: (s) => ({
				"token-endpoint": { url: s["token-endpoint"], hosts: hostsOf(s) },
				api: { url: userUrl(s.api), hosts: hostsOf(s) },
			}),
		}),
	);

export type Settings = z.output<typeof section>;
