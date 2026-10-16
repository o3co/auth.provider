import type { OutboundPolicy } from "@mod/outbound";
import {
	clientSetting,
	endpointSetting as endpoint,
	scopeSetting as scope,
} from "@mod/upstream-client";
import { z } from "zod";

/** Where the user is read. */
export const userUrl = (api: string) => `${api.replace(/\/$/, "")}/user`;

/** The hosts requests are narrowed to: the token endpoint's and the API's. */
export const hostsOf = (s: { readonly "token-endpoint": string; readonly api: string }) => [
	...new Set([s["token-endpoint"], s.api].map((url) => new URL(url).hostname)),
];

const section = clientSetting.extend({
	scopes: z.array(scope).default(["read:user"]),
	/** GitHub's own unless the operator names another (GitHub Enterprise). */
	"authorization-endpoint": endpoint.default("https://github.com/login/oauth/authorize"),
	"token-endpoint": endpoint.default("https://github.com/login/oauth/access_token"),
	api: endpoint.default("https://api.github.com"),
	/** The `iss` a callback carries, where it carries one (RFC 9207). */
	issuer: z.string().min(1).default("https://github.com/login/oauth"),
});

/** The section; boot is refused on a URL it sends to that outbound's destination policy refuses. */
export const settingsOf = (policy: OutboundPolicy) =>
	section.superRefine((s, context) => {
		const sent = { "token-endpoint": s["token-endpoint"], api: userUrl(s.api) };
		for (const [key, url] of Object.entries(sent)) {
			const refusal = policy.refusalOf(url, { hosts: hostsOf(s) });
			if (refusal === undefined) continue;
			const message = `outbound's destination policy refuses it: ${refusal}`;
			context.addIssue({ code: "custom", path: [key], message });
		}
	});

export type Settings = z.output<typeof section>;
