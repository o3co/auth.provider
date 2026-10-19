import { setting } from "@mod/kernel";
import type { OutboundPolicy } from "@mod/outbound";
import { clientSetting, endpointSetting as endpoint } from "@mod/upstream-client";
import { z } from "zod";

const section = clientSetting.extend({
	access: z
		.enum(["offline", "online"])
		.prefault("offline")
		.describe(
			"`offline` asks for a refresh token, so Google shows its consent screen at every login; `online` asks none.",
		),
	"require-iss": z
		.boolean()
		.prefault(true)
		.describe("Asks every callback for `iss`, which Google says it always sends."),
	"authorization-endpoint": endpoint
		.prefault("https://accounts.google.com/o/oauth2/v2/auth")
		.describe("Where the browser is sent to log in at Google; Google's own unless named."),
	"token-endpoint": endpoint
		.prefault("https://oauth2.googleapis.com/token")
		.describe("Where a code is exchanged for tokens; Google's own unless named."),
	"jwks-uri": endpoint
		.prefault("https://www.googleapis.com/oauth2/v3/certs")
		.describe("Where the keys that sign Google's id_tokens are read; Google's own unless named."),
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
export const settingsOf = (policy: OutboundPolicy) =>
	section.superRefine((s, context) => {
		for (const key of ["token-endpoint", "jwks-uri"] as const) {
			// A value that is no URL is refused already, and zod still runs this: it is passed over.
			if (!URL.canParse(s[key])) continue;
			const refusal = policy.refusalOf(s[key], { hosts: [new URL(s[key]).hostname] });
			if (refusal === undefined) continue;
			const message = `outbound's destination policy refuses it: ${refusal}`;
			context.addIssue({ code: "custom", path: [key], message });
		}
	});

export type Settings = z.output<typeof section>;
