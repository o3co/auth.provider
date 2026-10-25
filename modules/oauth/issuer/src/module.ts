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

export default defineModule({ name: "issuer", section, takes: [site, metadata] }, (m) => [
	m.provide(issuer).by(async (c) => {
		const url = c.section.url;
		const publicOrigin = (await c.get(site)).origin;
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
]);
