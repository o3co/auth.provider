import { setting } from "@mod/kernel";
import type { OutboundRefusals } from "@mod/outbound";
import {
	clientSetting,
	credentialSetting,
	endpointSetting as endpoint,
} from "@mod/upstream-client";
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
	section.superRefine((s, context) => {
		for (const key of ["token-endpoint", "jwks-uri"] as const) {
			// A value that is no URL is refused already, and zod still runs this: it is passed over.
			if (!URL.canParse(s[key])) continue;
			const refused = refusals.explained(s[key], { hosts: [new URL(s[key]).hostname] });
			if (refused === undefined) continue;
			const message = `outbound's destination policy refuses it: ${refused}`;
			context.addIssue({ code: "custom", path: [key], message });
		}
	});

export type Settings = z.output<typeof section>;
