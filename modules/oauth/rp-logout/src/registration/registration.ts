import type { Client, Section } from "@mod/clients";
import type { BuildContext } from "@mod/kernel";
import { destinationRefusal, type OutboundRefusals, outboundRefusals } from "@mod/outbound-policy";
import { redirectsAt, registrable } from "@mod/redirect-uris";
import { z } from "zod";

/** What a client registers for logouts. */
export interface Registration {
	readonly "post-logout-redirect-uris": readonly string[];
	readonly "frontchannel-logout-uri"?: string | undefined;
	readonly "frontchannel-logout-session-required": boolean;
	readonly "backchannel-logout-uri"?: string | undefined;
	readonly "backchannel-logout-session-required": boolean;
}

/** The URL parser reads past spaces and controls, so the string checked would not be the one used. */
const plain = (uri: string) => !/[\s\p{Cc}]/u.test(uri);
/** The URL when it is an http or https one without userinfo or a fragment; none otherwise. */
const httpUrl = (uri: string) => {
	const url = plain(uri) ? URL.parse(uri) : null;
	const web = url?.protocol === "https:" || url?.protocol === "http:";
	return web && url.username === "" && url.password === "" && url.hash === "" ? url : undefined;
};
/** OpenID Connect Front-Channel Logout 1.0 §2: the provider adds `iss` and `sid` itself; any spelling of them is refused. */
const namesIssOrSid = (name: string) =>
	["iss", "sid"].includes(name.toLowerCase().replace(/[-_]/g, ""));
const frontChannel = (uri: string) => {
	const url = httpUrl(uri);
	return url !== undefined && ![...url.searchParams.keys()].some(namesIssOrSid);
};

/**
 * OpenID Connect Front-Channel Logout 1.0 §2: a front-channel URL's scheme, host and port are one of
 * the client's redirect URIs'. Checked at boot for a registered client, and again before framing.
 */
export const framable = (registered: Registration, client: Client): boolean => {
	const uri = registered["frontchannel-logout-uri"];
	return uri === undefined || redirectsAt(client, new URL(uri).origin);
};

/** Whether `client`, as its record says now, registers `uri` exactly as a return; none for no client. */
export const returnsTo = (client: Client | undefined, uri: string): boolean =>
	client?.section(registration)["post-logout-redirect-uris"].includes(uri) ?? false;

export const registration: Section<Registration> = {
	name: "rp-logout",
	schema: z.strictObject({
		"post-logout-redirect-uris": z
			.array(z.string().refine(registrable, "a URI a client may register to be sent back to"))
			.prefault([])
			.describe(
				"Where a logout may send the browser back to, each a URI `redirect-uris` lets a client register; a return asked for is used only when it matches one exactly.",
			),
		"frontchannel-logout-uri": z
			.string()
			.refine(frontChannel, "an http or https URL without iss or sid in its query")
			.optional()
			.describe(
				"The page framed after a logout (OpenID Connect Front-Channel Logout 1.0): an http or https URL without userinfo, a fragment, or iss or sid in its query, at one of the client's redirect URIs' origins.",
			),
		"frontchannel-logout-session-required": z
			.boolean()
			.prefault(true)
			.describe("Whether the framed page's URL gets the session's sid beside iss."),
		"backchannel-logout-uri": z
			.string()
			.refine((uri) => httpUrl(uri) !== undefined, "an http or https URL")
			.optional()
			.describe(
				"Where the logout token is posted after a logout (OpenID Connect Back-Channel Logout 1.0): an http or https URL without userinfo or a fragment.",
			),
		"backchannel-logout-session-required": z
			.boolean()
			.prefault(true)
			.describe("Whether the logout token carries the session's sid."),
	}),
	checkAtBoot: (value, client) =>
		framable(value, client)
			? undefined
			: "frontchannel-logout-uri is at none of its redirect URIs' origins",
};

/**
 * The section with a boot check that `outbound`'s policy lets a registered client's back channel
 * through, as the logout token is posted to it: one it refuses would be dropped at every logout.
 */
export function registrationUnder(refusals: OutboundRefusals): Section<Registration> {
	return {
		...registration,
		checkAtBoot: (value, client) => {
			const framed = registration.checkAtBoot?.(value, client);
			if (framed) return framed;
			const uri = value["backchannel-logout-uri"];
			return uri === undefined
				? undefined
				: destinationRefusal(refusals, uri, undefined, "the backchannel-logout-uri");
		},
	};
}

/** The section as the composition gives it, with `outbound`'s refusals read from it. */
export async function registrationIn(
	c: Pick<BuildContext<unknown>, "get">,
): Promise<Section<Registration>> {
	return registrationUnder(await c.get(outboundRefusals));
}
