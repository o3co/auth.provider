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
			issuer: endpoint.describe(
				"The IdP's issuer, which its id_tokens name and its description sits under.",
			),
			"token-auth": z
				.enum(["client_secret_basic", "client_secret_post"])
				.prefault("client_secret_basic")
				.describe("How the client authenticates at the token endpoint."),
			discovery: z
				.boolean()
				.prefault(true)
				.describe(
					"Reads the endpoints from the issuer's own description, checking it names the issuer; without it, the three endpoints are given.",
				),
			"authorization-endpoint": endpoint
				.optional()
				.describe("Where the browser is sent to log in, without discovery."),
			"token-endpoint": endpoint
				.optional()
				.describe("Where a code is exchanged for tokens, without discovery."),
			"jwks-uri": endpoint
				.optional()
				.describe("Where the keys that sign the IdP's id_tokens are read, without discovery."),
			"end-session-endpoint": endpoint
				.optional()
				.describe("Where a session at the IdP ends, without discovery; none when not given."),
			scopes: z
				.array(scope)
				.prefault(["openid"])
				.refine((scopes) => scopes.includes("openid"), "scopes must hold openid")
				.describe("The scopes asked of the IdP at a login, `openid` among them."),
			algorithms: z
				.array(z.enum(asymmetric as [Algorithm, ...Algorithm[]]))
				.min(1)
				.prefault(["RS256", "PS256", "ES256", "EdDSA"])
				.describe("The algorithms an id_token may be signed with: asymmetric ones only."),
			"endpoint-hosts": z
				.array(z.string().refine((entry) => hostEntryOf(entry) !== undefined, "a host, or .name"))
				.prefault([])
				.describe(
					"Hosts besides the issuer's its endpoints may be on, as outbound reads a host list.",
				),
			"require-iss": z
				.boolean()
				.prefault(false)
				.describe(
					"Asks every callback for `iss`, even where the issuer's description does not offer it.",
				),
			"clock-skew": setting
				.duration("s")
				.pipe(z.number().int().min(0).max(300))
				.prefault("30s")
				.describe("How far the IdP's clock may be from ours, for its id_token's times: 0s to 5m."),
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
			// A value that is no URL is refused already, and zod still runs this: it is passed over.
			const urls = [s.issuer, s["authorization-endpoint"], s["token-endpoint"], s["jwks-uri"]];
			if (!urls.every((url) => url === undefined || URL.canParse(url))) return;
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
