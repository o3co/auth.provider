import { algorithmsSetting, knownAlgorithms } from "@mod/external-jwt";
import { setting } from "@mod/kernel";
import {
	browsedRefusalText,
	destinationRefusal,
	type OutboundRefusals,
} from "@mod/outbound-policy";
import {
	clientSetting,
	credentialSetting,
	endpointSetting as endpoint,
} from "@mod/upstream-client";
import { urlsChecked } from "@mod/url-setting";
import { z } from "zod";

/** The three settings that sign the client's secret, together. */
const signing = ["team-id", "key-id", "private-key"] as const;

/** The Services ID as `client-id`, and its secret: a fixed one, or one the team's key signs. */
const section = clientSetting
	.extend({
		"client-secret": credentialSetting
			.optional()
			.describe("A fixed client secret, in place of the three that sign one."),
		"team-id": credentialSetting
			.optional()
			.describe("The Apple team that signs the client secret, with key-id and private-key."),
		"key-id": credentialSetting
			.optional()
			.describe(
				"The ID of the team's key that signs the client secret, with team-id and private-key.",
			),
		"private-key": credentialSetting
			.optional()
			.describe("The team's P-256 key, as PKCS8 PEM, that signs the client secret."),
		"secret-lifetime": setting
			.duration("s")
			.pipe(z.number().int().min(60).max(15_777_000))
			.prefault("5m")
			.describe("How long a signed client secret lives: 1m to 15777000s (about half a year)."),
		scopes: z
			.array(z.enum(["name", "email"]))
			.prefault(["email"])
			.describe("The scopes asked of Apple at a login: `name`, `email` or both."),
		"authorization-endpoint": endpoint
			.prefault("https://appleid.apple.com/auth/authorize")
			.describe("Where the browser is sent to log in at Apple; Apple's own unless named."),
		"token-endpoint": endpoint
			.prefault("https://appleid.apple.com/auth/token")
			.describe("Where a code is exchanged for tokens; Apple's own unless named."),
		"jwks-uri": endpoint
			.prefault("https://appleid.apple.com/auth/keys")
			.describe("Where the keys that sign Apple's id_tokens are read; Apple's own unless named."),
		algorithms: algorithmsSetting(knownAlgorithms, ["RS256"]).describe(
			"The algorithms Apple's id_tokens may be signed with: asymmetric ones only, RS256 by default, the one Apple signs with.",
		),
		"clock-skew": setting
			.duration("s")
			.pipe(z.number().int().min(0).max(300))
			.prefault("30s")
			.describe("How far Apple's clock may be from ours, for its id_token's times: 0s to 5m."),
		"end-session-endpoint": endpoint
			.optional()
			.describe("Where to end the session at Apple, which has none of its own."),
	})
	.superRefine((s, context) => {
		const given = signing.filter((name) => s[name] !== undefined);
		if ((s["client-secret"] === undefined) === (given.length === 0)) {
			context.addIssue({
				code: "custom",
				message: "give either client-secret or team-id, key-id and private-key, not both",
			});
			return;
		}
		for (const name of signing) {
			if (given.length > 0 && s[name] === undefined) {
				context.addIssue({
					code: "custom",
					path: [name],
					message: "team-id, key-id and private-key sign the secret together",
				});
			}
		}
	});

/**
 * The section; boot is refused on an endpoint this server sends to, Apple's own included, that
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
			// The browser goes to these; Apple is a public service, so plain http is taken at a loopback name alone.
			for (const key of ["authorization-endpoint", "end-session-endpoint"] as const) {
				const url = s[key];
				// Its own schema refuses a URL that does not parse.
				if (url === undefined || !URL.canParse(url)) continue;
				const refused = browsedRefusalText(refusals, url);
				if (refused) context.addIssue({ code: "custom", path: [key], message: refused });
			}
		});

export type Settings = z.output<typeof section>;
