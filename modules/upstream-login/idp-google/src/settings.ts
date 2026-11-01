import { algorithmsSetting, knownAlgorithms } from "@mod/external-jwt";
import { setting } from "@mod/kernel";
import {
	browsedRefusalText,
	destinationRefusal,
	type OutboundRefusals,
} from "@mod/outbound-policy";
import { clientSetting, endpointSetting as endpoint } from "@mod/upstream-client";
import { urlsChecked } from "@mod/url-setting";
import { z } from "zod";

const section = clientSetting.extend({
	access: z
		.enum(["offline", "online"])
		.prefault("offline")
		.describe(
			"`offline` asks for a refresh token, so Google shows its consent screen at every login; `online` asks none.",
		),
	"accept-missing-iss": z
		.boolean()
		.prefault(false)
		.describe(
			"Takes a callback without `iss`, which Google says it always sends; warned of at every start.",
		),
	"authorization-endpoint": endpoint
		.prefault("https://accounts.google.com/o/oauth2/v2/auth")
		.describe("Where the browser is sent to log in at Google; Google's own unless named."),
	"token-endpoint": endpoint
		.prefault("https://oauth2.googleapis.com/token")
		.describe("Where a code is exchanged for tokens; Google's own unless named."),
	"jwks-uri": endpoint
		.prefault("https://www.googleapis.com/oauth2/v3/certs")
		.describe("Where the keys that sign Google's id_tokens are read; Google's own unless named."),
	algorithms: algorithmsSetting(knownAlgorithms, ["RS256"]).describe(
		"The algorithms Google's id_tokens may be signed with: asymmetric ones only, RS256 by default, the one Google signs with.",
	),
	"clock-skew": setting
		.duration("s")
		.pipe(z.number().int().min(0).max(300))
		.prefault("30s")
		.describe("How far Google's clock may be from ours, for its id_token's times: 0s to 5m."),
	"end-session-endpoint": endpoint
		.optional()
		.describe(
			"Where to end the session at Google; without it, the browser goes back or to Google's logout page.",
		),
	"hosted-domains": z
		.array(z.string().regex(/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/, "a domain, lowercase"))
		.min(1)
		.optional()
		.describe(
			"The Google Workspace domains a login must be from, by its id_token's `hd`; any account when not given.",
		),
});

/**
 * The section; boot is refused on an endpoint this server sends to, Google's own included, that
 * outbound's destination policy refuses with the endpoint's host alone.
 */
export const settingsOf = (refusals: OutboundRefusals) =>
	section
		.superRefine(
			urlsChecked((url, hosts) => destinationRefusal(refusals, url, { hosts }), {
				urls: (s) => [s["token-endpoint"], s["jwks-uri"]],
				sent: (s) => ({
					"token-endpoint": {
						url: s["token-endpoint"],
						hosts: [new URL(s["token-endpoint"]).hostname],
					},
					"jwks-uri": { url: s["jwks-uri"], hosts: [new URL(s["jwks-uri"]).hostname] },
				}),
			}),
		)
		.superRefine((s, context) => {
			// The browser goes to these; Google is a public service, so plain http is taken at a loopback name alone.
			for (const key of ["authorization-endpoint", "end-session-endpoint"] as const) {
				const url = s[key];
				// Its own schema refuses a URL that does not parse.
				if (url === undefined || !URL.canParse(url)) continue;
				const refused = browsedRefusalText(refusals, url);
				if (refused) context.addIssue({ code: "custom", path: [key], message: refused });
			}
		});

export type Settings = z.output<typeof section>;
