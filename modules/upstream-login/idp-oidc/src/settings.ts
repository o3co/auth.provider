import type { Algorithm } from "@mod/external-jwt";
import { setting } from "@mod/kernel";
import {
	destinationRefusal,
	hostEntryOf,
	type Narrower,
	type OutboundRefusals,
} from "@mod/outbound-policy";
import {
	clientSetting,
	endpointSetting as endpoint,
	scopeSetting as scope,
} from "@mod/upstream-client";
import { type ConfiguredUrl, urlsChecked } from "@mod/url-setting";
import { z } from "zod";

/** Where the issuer describes itself. */
export const descriptionUrl = (issuer: string) =>
	`${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;

/**
 * The operator's URL each request is sent for, which outbound may reach as theirs: the issuer for
 * everything its description names, else each given endpoint for itself. Nothing a description
 * names becomes one.
 */
export const sentFor = (s: {
	readonly discovery: boolean;
	readonly issuer: ConfiguredUrl;
	readonly "token-endpoint"?: ConfiguredUrl | undefined;
	readonly "jwks-uri"?: ConfiguredUrl | undefined;
}) =>
	s.discovery
		? { token: s.issuer, jwks: s.issuer }
		: { token: s["token-endpoint"], jwks: s["jwks-uri"] };

/** How a request to the upstream is narrowed: its hosts, and the operator's URL it is sent for. */
export const narrowerOf = (hosts: readonly string[], internal: ConfiguredUrl | undefined) => ({
	hosts,
	...(internal === undefined ? {} : { internal }),
});

/** The hosts requests to the upstream are narrowed to: the issuer's, the named ones, the given endpoints'. */
/**
 * Why outbound's policy for a URL the browser goes to refuses it, as boot says it, naming `what`;
 * a policy that does not say refuses all but https.
 */
export function browsedRefusal(
	refusals: OutboundRefusals,
	url: string,
	narrower: Narrower,
	what: string,
): string | undefined {
	const reason = refusals.browsedRefusal
		? refusals.browsedRefusal(url, narrower)
		: URL.parse(url)?.protocol === "https:"
			? undefined
			: "not https";
	return reason && `outbound's policy for what the browser goes to refuses ${what}: ${reason}`;
}

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
export const settingsOf = (asymmetric: readonly Algorithm[], refusals: OutboundRefusals) =>
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
		.superRefine(
			// Asked with the same narrowing as the requests themselves.
			urlsChecked(
				(url, hosts, internal) => destinationRefusal(refusals, url, narrowerOf(hosts, internal)),
				{
					urls: (s) => [s.issuer, s["authorization-endpoint"], s["token-endpoint"], s["jwks-uri"]],
					sent: (s) => {
						const hosts = hostsOf(s);
						const from = sentFor(s);
						return s.discovery
							? { issuer: { url: descriptionUrl(s.issuer), hosts, internal: s.issuer } }
							: {
									"token-endpoint": { url: s["token-endpoint"], hosts, internal: from.token },
									"jwks-uri": { url: s["jwks-uri"], hosts, internal: from.jwks },
								};
					},
				},
			),
		)
		.superRefine((s, context) => {
			// The browser goes to these, each given endpoint the operator's URL for itself alone.
			if (s.discovery) return;
			for (const key of ["authorization-endpoint", "end-session-endpoint"] as const) {
				const url = s[key];
				// Its own schema refuses a URL that does not parse.
				if (url === undefined || !URL.canParse(url)) continue;
				const refused = browsedRefusal(refusals, url, { internal: url }, "it");
				if (refused) context.addIssue({ code: "custom", path: [key], message: refused });
			}
		});

export type Settings = z.output<ReturnType<typeof settingsOf>>;
