import { setting } from "@mod/kernel";
import type { OutboundPolicy } from "@mod/outbound";
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
		/** A fixed secret, in place of the three that sign one. */
		"client-secret": credentialSetting.optional(),
		"team-id": credentialSetting.optional(),
		"key-id": credentialSetting.optional(),
		/** The team's P-256 key, as PKCS8 PEM. */
		"private-key": credentialSetting.optional(),
		/** How long a signed secret lives: 1m to 15777000s (about half a year). */
		"secret-lifetime": setting
			.duration("s")
			.pipe(z.number().int().min(60).max(15_777_000))
			.prefault("5m"),
		scopes: z.array(z.enum(["name", "email"])).prefault(["email"]),
		/** Apple's own unless the operator names others. */
		"authorization-endpoint": endpoint.prefault("https://appleid.apple.com/auth/authorize"),
		"token-endpoint": endpoint.prefault("https://appleid.apple.com/auth/token"),
		"jwks-uri": endpoint.prefault("https://appleid.apple.com/auth/keys"),
		/** How far Apple's clock may be from ours, for its id_token's times: 0s to 5m. */
		"clock-skew": setting.duration("s").pipe(z.number().int().min(0).max(300)).prefault("30s"),
		/** Where to end the upstream session; Apple has none of its own. */
		"end-session-endpoint": endpoint.optional(),
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
