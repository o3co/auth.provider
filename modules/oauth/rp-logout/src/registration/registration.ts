import { redirectsAt, registrable } from "@mod/authorize";
import type { Client, Section } from "@mod/clients";
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

export const registration: Section<Registration> = {
	name: "rp-logout",
	schema: z.strictObject({
		"post-logout-redirect-uris": z
			.array(z.string().refine(registrable, "a URI a client may register to be sent back to"))
			.prefault([]),
		"frontchannel-logout-uri": z
			.string()
			.refine(frontChannel, "an http or https URL without iss or sid in its query")
			.optional(),
		"frontchannel-logout-session-required": z.boolean().prefault(true),
		"backchannel-logout-uri": z
			.string()
			.refine((uri) => httpUrl(uri) !== undefined, "an http or https URL")
			.optional(),
		"backchannel-logout-session-required": z.boolean().prefault(true),
	}),
	checkAtBoot: (value, client) =>
		framable(value, client)
			? undefined
			: "frontchannel-logout-uri is at none of its redirect URIs' origins",
};
