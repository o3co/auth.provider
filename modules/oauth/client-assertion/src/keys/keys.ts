import type { Section } from "@mod/clients";
import type { KeySource } from "@mod/external-jwt";
import type { BuildContext } from "@mod/kernel";
import { publicJwk, verifiesUnder } from "@mod/keys";
import { destinationRefusal, type OutboundRefusals, outboundRefusals } from "@mod/outbound-policy";
import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export type Jwk = Readonly<Record<string, unknown>>;

/** A public key for verifying signatures, read by `keys`' rules. */
const verifiesSignatures = (jwk: Jwk) => publicJwk(jwk) !== undefined && verifiesUnder(jwk);

/** The client's keys for its assertions: public keys written into its record, or a key set's URL. */
export interface ClientKeys {
	readonly keys: readonly Jwk[];
	readonly "jwks-uri"?: string | undefined;
	/** Also takes the token endpoint's URL, or a list, as an assertion's audience. */
	readonly "accept-loose-audience": boolean;
}

export const clientKeys: Section<ClientKeys> = {
	name: "client-assertion",
	schema: z
		.strictObject({
			keys: z
				.array(
					z
						.record(z.string(), z.unknown())
						.refine(verifiesSignatures, "a public RSA, EC or OKP key for verifying signatures"),
				)
				.prefault([])
				.describe(
					"The client's public keys for its assertions, as JWKs: RSA, EC or OKP, with no private member; never beside `jwks-uri`.",
				),
			"jwks-uri": urlSetting({ schemes: ["https", "http"] })
				.optional()
				.describe(
					"Where the client publishes its key set, an https URL (http only where `outbound` allows plain http); never beside written `keys`. A registered client's one that `outbound` refuses refuses boot.",
				),
			"accept-loose-audience": z
				.boolean()
				.prefault(false)
				.describe(
					"Also takes, from this client, an assertion whose `aud` is the token endpoint's URL or a list holding the issuer's or the token endpoint's URL, as 0.18.5 did; each is logged. While set, an assertion the client made for another authorization server that names this one's token endpoint can be used here. For a client whose library names the token endpoint; a registered client that sets it is warned of at every start.",
				),
		})
		.refine((s) => s.keys.length === 0 || s["jwks-uri"] === undefined, {
			message: "keys written in, or a jwks-uri, not both",
			path: ["jwks-uri"],
		}),
};

/** Where the client's keys come from: its key set's URL, fetched from that URL's host alone, or its written keys. */
export function keysOf(section: ClientKeys): KeySource {
	const uri = section["jwks-uri"];
	return uri === undefined
		? { inline: section.keys }
		: { jwks: { url: uri, hosts: [new URL(uri).hostname] } };
}

/** The section with a check at boot that `outbound`'s policy lets a registered client's jwks-uri through. */
export function clientKeysUnder(refusals: OutboundRefusals): Section<ClientKeys> {
	return {
		...clientKeys,
		checkAtBoot: (section) => {
			const source = keysOf(section);
			if (!("jwks" in source)) return undefined;
			return destinationRefusal(
				refusals,
				source.jwks.url,
				{ hosts: source.jwks.hosts },
				"the jwks-uri",
			);
		},
	};
}

/** What `clientKeysIn` takes from the build context. */
export const keysTakes = [outboundRefusals] as const;

/** The section as the composition gives it, with `outbound`'s refusals read from it. */
export async function clientKeysIn(
	c: Pick<BuildContext<unknown>, "get">,
): Promise<Section<ClientKeys>> {
	return clientKeysUnder(await c.get(outboundRefusals));
}
