import type { OutboundPolicy } from "@mod/outbound";
import { clientSetting, endpointSetting as endpoint } from "@mod/upstream-client";
import { z } from "zod";

const section = clientSetting.extend({
	/** `offline` asks for a refresh token, so Google shows its consent screen at every login. */
	access: z.enum(["offline", "online"]).default("offline"),
	/** Asks every callback for `iss`, which Google says it always sends. */
	"require-iss": z.boolean().default(true),
	/** Google's own unless the operator names others. */
	"authorization-endpoint": endpoint.default("https://accounts.google.com/o/oauth2/v2/auth"),
	"token-endpoint": endpoint.default("https://oauth2.googleapis.com/token"),
	"jwks-uri": endpoint.default("https://www.googleapis.com/oauth2/v3/certs"),
	/** How far Google's clock may be from ours, for its id_token's times. */
	"clock-skew-seconds": z.number().int().min(0).max(300).default(30),
	/** Where to end the upstream session; without it, the browser goes back or to Google's logout page. */
	"end-session-endpoint": endpoint.optional(),
});

/**
 * The section; boot is refused on an endpoint this server sends to, Google's own included, that
 * outbound's destination policy refuses with the endpoint's host alone.
 */
export const settingsOf = (policy: OutboundPolicy) =>
	section.superRefine((s, context) => {
		for (const key of ["token-endpoint", "jwks-uri"] as const) {
			const refusal = policy.refusalOf(s[key], { hosts: [new URL(s[key]).hostname] });
			if (refusal === undefined) continue;
			const message = `outbound's destination policy refuses it: ${refusal}`;
			context.addIssue({ code: "custom", path: [key], message });
		}
	});

export type Settings = z.output<typeof section>;
