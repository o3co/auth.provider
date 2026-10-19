import type { Algorithm } from "@mod/external-jwt";
import { setting } from "@mod/kernel";
import { hostEntryOf, type OutboundPolicy } from "@mod/outbound";
import {
	clientSetting,
	endpointSetting as endpoint,
	scopeSetting as scope,
} from "@mod/upstream-client";
import { z } from "zod";

/** Where the issuer describes itself. */
export const descriptionUrl = (issuer: string) =>
	`${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;

/** The hosts requests to the upstream are narrowed to: the issuer's, the named ones, the given endpoints'. */
export function hostsOf(s: {
	readonly issuer: string;
	readonly "endpoint-hosts": readonly string[];
	readonly "authorization-endpoint"?: string | undefined;
	readonly "token-endpoint"?: string | undefined;
	readonly "jwks-uri"?: string | undefined;
}): readonly string[] {
	const named = [s["authorization-endpoint"], s["token-endpoint"], s["jwks-uri"]];
	const hostOf = (url: string) => new URL(url).hostname;
	const given = named.filter((url) => url !== undefined).map(hostOf);
	return [...new Set([hostOf(s.issuer), ...s["endpoint-hosts"], ...given])];
}

/**
 * The section, taking only the asymmetric algorithms external-jwt knows: never none nor HMAC. Boot is
 * refused on a URL it sends to that outbound's destination policy refuses.
 */
export const settingsOf = (asymmetric: readonly Algorithm[], policy: OutboundPolicy) =>
	clientSetting
		.extend({
			issuer: endpoint,
			"token-auth": z
				.enum(["client_secret_basic", "client_secret_post"])
				.prefault("client_secret_basic"),
			/** Reads the endpoints from the issuer's own description, checking it names the issuer. */
			discovery: z.boolean().prefault(true),
			"authorization-endpoint": endpoint.optional(),
			"token-endpoint": endpoint.optional(),
			"jwks-uri": endpoint.optional(),
			/** Where a session at the upstream ends, without discovery; none when not given. */
			"end-session-endpoint": endpoint.optional(),
			scopes: z
				.array(scope)
				.prefault(["openid"])
				.refine((scopes) => scopes.includes("openid"), "scopes must hold openid"),
			algorithms: z
				.array(z.enum(asymmetric as [Algorithm, ...Algorithm[]]))
				.min(1)
				.prefault(["RS256", "PS256", "ES256", "EdDSA"]),
			/** Hosts besides the issuer's its endpoints may be on, as outbound reads a host list. */
			"endpoint-hosts": z
				.array(z.string().refine((entry) => hostEntryOf(entry) !== undefined, "a host, or .name"))
				.prefault([]),
			/** Asks every callback for `iss`, even where the issuer's description does not offer it. */
			"require-iss": z.boolean().prefault(false),
			/** How far the upstream's clock may be from ours, for its id_token's times: 0s to 5m. */
			"clock-skew": setting.duration("s").pipe(z.number().int().min(0).max(300)).prefault("30s"),
		})
		.refine(
			(s) =>
				s.discovery
					? !s["authorization-endpoint"] &&
						!s["token-endpoint"] &&
						!s["jwks-uri"] &&
						!s["end-session-endpoint"]
					: Boolean(s["authorization-endpoint"] && s["token-endpoint"] && s["jwks-uri"]),
			{
				message: "the endpoints come from discovery, or all three are given without it",
				path: ["discovery"],
			},
		)
		.superRefine((s, context) => {
			const sent = s.discovery
				? { issuer: descriptionUrl(s.issuer) }
				: { "token-endpoint": s["token-endpoint"], "jwks-uri": s["jwks-uri"] };
			const hosts = hostsOf(s);
			for (const [key, url] of Object.entries(sent)) {
				const refusal = url === undefined ? undefined : policy.refusalOf(url, { hosts });
				if (refusal === undefined) continue;
				const message = `outbound's destination policy refuses it: ${refusal}`;
				context.addIssue({ code: "custom", path: [key], message });
			}
		});

export type Settings = z.output<ReturnType<typeof settingsOf>>;
