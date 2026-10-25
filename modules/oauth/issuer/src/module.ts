import { site } from "@mod/http";
import { contract, defineModule } from "@mod/kernel";
import { issuer, type MetadataItem, metadata } from "./contract.ts";
import { section } from "./section.ts";

/**
 * Never read: the kernel builds every provider at boot, so providing this runs the item check
 * whether or not any module collects the items. Kept apart from `issuer`, which contributors may
 * need while built.
 */
const itemsChecked = contract<readonly MetadataItem[]>("issuer.items");

export default defineModule(
	{
		name: "issuer",
		section,
		// Tokens and the discovery document would name a plain-http issuer, open to being changed.
		refusedInProduction: (s) =>
			s.url.startsWith("http:")
				? [
						{
							key: "url",
							reason:
								"is plain http, which a production deployment does not take; set kernel.environment = development to try one",
						},
					]
				: [],
		takes: [site, metadata],
	},
	(m) => [
		m.provide(issuer).by(async (c) => {
			const url = c.section.url;
			const publicOrigin = (await c.get(site)).origin;
			// Plain http only as the public origin's own, which http takes only with insecure-origin: no
			// public origin leaves nothing to say the deployment accepted it.
			if (publicOrigin === undefined && url.startsWith("http:")) {
				return c.refuse(
					"issuer.url",
					"a plain-http issuer needs the same plain-http public origin, accepted by http.insecure-origin",
				);
			}
			if (publicOrigin !== undefined && new URL(url).origin !== publicOrigin) {
				return c.refuse(
					"issuer.url",
					"the issuer origin differs from this deployment's public origin",
				);
			}
			return Object.freeze({ url });
		}),
		m.provide(itemsChecked).by(async (c) => {
			const contributed = await c.collect(metadata);
			if (contributed.some((item) => item.name === "issuer")) {
				return c.refuse(
					`${metadata.label}:issuer`,
					"the issuer item is the URL, never a contribution",
				);
			}
			return contributed;
		}),
	],
);
