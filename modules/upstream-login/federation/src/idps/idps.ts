import { type Site, site } from "@mod/http";
import type { BuildContext, Refusal } from "@mod/kernel";
import { type IdpType, idpTypes } from "@mod/upstreams";
import { callbackPath, federationIdps, type Idp, proves } from "../round-trip/round-trip.ts";
import type { Settings } from "../section.ts";

interface Parts {
	readonly types: readonly IdpType[];
	readonly settings: Settings["idps"];
	readonly site: Pick<Site, "origin" | "secureCookies">;
}

export async function idpsIn(c: BuildContext<Settings>) {
	const { idps, refusals } = await openIdps({
		types: await c.collect(idpTypes),
		settings: c.section.idps,
		site: await c.get(site),
	});
	if (refusals.length > 0) c.refuseAll(refusals);
	return idps;
}

/** `upstreams` over the opened IdPs: each one's refresh, end of session and delegation. */
const upstreamsWith = (idps: ReadonlyMap<string, Idp>) => ({
	of: (idp: string) => {
		const upstream = idps.get(idp)?.upstream;
		if (!upstream) return undefined;
		// Only what it offers besides a login: never its authorization URL or code exchange.
		const { refresh, endSession, delegation } = upstream;
		return {
			...(refresh ? { refresh } : {}),
			...(endSession ? { endSession } : {}),
			...(delegation ? { delegation } : {}),
		};
	},
});

export const upstreamsIn = async (c: BuildContext<Settings>) =>
	upstreamsWith(await c.get(federationIdps));

/** login-gates' amr source: what a federation login proves, and what the IdPs' amr maps to. */
const amrSourceWith = (settings: Settings["idps"]) => ({
	name: "federation",
	amr: [
		...new Set([
			...proves,
			...Object.values(settings).flatMap((idp) => Object.values(idp["upstream-amr"])),
		]),
	],
});

export const amrSourceIn = (c: BuildContext<Settings>) => amrSourceWith(c.section.idps);

/** The type's upstream for the settings, or nothing where the type refuses it (boot is then refused). */
async function openUpstream(
	idpType: IdpType,
	settings: unknown,
	at: { name: string; redirectUri: string },
) {
	try {
		return await idpType.open(settings, at);
	} catch {
		return undefined;
	}
}

/** Opens every configured IdP through its type, with every problem found, so boot is refused once. */
export async function openIdps(parts: Parts) {
	const origin = parts.site.origin;
	const types = new Map(parts.types.map((type) => [type.type, type]));
	const idps = new Map<string, Idp>();
	const refusals: Refusal[] = [];
	for (const [name, { type, "upstream-amr": upstreamAmr, ...rest }] of Object.entries(
		parts.settings,
	)) {
		const where = `federation.idps.${name}`;
		const idpType = types.get(type);
		if (!idpType) {
			refusals.push({ where: `${where}.type`, reason: "no module offers this IdP type" });
			continue;
		}
		const settings = idpType.settings.safeParse(rest);
		if (!settings.success) {
			for (const issue of settings.error.issues) {
				refusals.push({ where: [where, ...issue.path].join("."), reason: issue.message });
			}
			continue;
		}
		if (origin === undefined) {
			refusals.push({ where, reason: "an IdP needs http's public origin for its callback" });
			continue;
		}
		const redirectUri = `${origin}${callbackPath(name)}`;
		const upstream = await openUpstream(idpType, settings.data, { name, redirectUri });
		if (!upstream) {
			refusals.push({ where, reason: "the upstream does not match its settings" });
			continue;
		}
		const formPost = upstream.responseMode === "form_post";
		if (formPost && !parts.site.secureCookies) {
			refusals.push({ where, reason: "an answer in form_post needs secure cookies" });
			continue;
		}
		idps.set(name, {
			upstream,
			formPost,
			redirectUri,
			upstreamAmr: new Map(Object.entries(upstreamAmr)),
		});
	}
	return { idps: idps as ReadonlyMap<string, Idp>, refusals };
}
