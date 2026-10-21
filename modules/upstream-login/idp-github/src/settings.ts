import {
	browsedRefusalText,
	destinationRefusal,
	type OutboundRefusals,
} from "@mod/outbound-policy";
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

/**
 * The section; boot is refused on a URL it sends to that outbound's destination policy refuses,
 * and on an authorization endpoint its policy for the browser refuses.
 */
export const settingsOf = (refusals: OutboundRefusals) =>
	section
		.superRefine(
			// Asked with the same narrowing as the requests: each sent for the endpoint the operator set.
			urlsChecked(
				(url, hosts, internal) =>
					destinationRefusal(refusals, url, { hosts, ...(internal ? { internal } : {}) }),
				{
					urls: (s) => [s["token-endpoint"], s.api],
					sent: (s) => ({
						"token-endpoint": {
							url: s["token-endpoint"],
							hosts: hostsOf(s),
							internal: s["token-endpoint"],
						},
						api: { url: userUrl(s.api), hosts: hostsOf(s), internal: s.api },
					}),
				},
			),
		)
		.superRefine((s, context) => {
			const url = s["authorization-endpoint"];
			// Its own schema refuses a URL that does not parse; the endpoint is the operator's URL for itself.
			if (!URL.canParse(url)) return;
			const refused = browsedRefusalText(refusals, url, { internal: url });
			if (refused)
				context.addIssue({ code: "custom", path: ["authorization-endpoint"], message: refused });
		});

export type Settings = z.output<typeof section>;
