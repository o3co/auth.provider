import { site } from "@mod/http";
import { type BuildContext, contract } from "@mod/kernel";
import { seal } from "@mod/seal";
import { revocations } from "@mod/subject-revocation";
import { upstreams } from "@mod/upstreams";
import { name, type Settings } from "../section.ts";
import { subjectGrants } from "../store.ts";
import {
	type Judge,
	judgeWith,
	type Listing,
	listingWith,
	type Records,
	recordsWith,
} from "./grant.ts";

export const sharedTakes = [seal, site, upstreams, revocations, subjectGrants] as const;

/** The records over `seal`. */
export const recordsOver = async (c: BuildContext<Settings>) => recordsWith(await c.get(seal));

/** The parts the other internal modules share, built once. */
export const shared = contract<{
	readonly origin: string;
	readonly records: Records;
	readonly judge: Judge;
	readonly listed: Listing;
}>("federation-grants.shared");

/** Builds the shared parts, refusing connections the deployment cannot serve. */
export async function sharedOver(c: BuildContext<Settings>) {
	const origin = (await c.get(site)).origin;
	const named = Object.entries(c.section.connections);
	if (named.length > 0 && !origin) c.refuse(name, "connections need the public origin");
	const found = await c.get(upstreams);
	for (const [connection, { idp }] of named) {
		if (!found.of(idp)?.delegation) {
			c.refuse(`${name}.connections.${connection}.idp`, "the IdP it names offers no delegation");
		}
	}
	const maxMs = c.section["max-lifetime"] * 1000;
	// The operator's choice, yet said at every start: a revoked subject's grants live on.
	if (c.section["keep-on-subject-revocation"]) {
		c.log.warn("federation-grants.kept_on_subject_revocation", {
			reason: "an established grant answers only to the delegations boundary of a revocation",
		});
	}
	return {
		origin: origin ?? "",
		records: await recordsOver(c),
		judge: judgeWith(await c.get(revocations), {
			keep: c.section["keep-on-subject-revocation"],
			maxMs,
		}),
		listed: listingWith(await c.get(subjectGrants), c.log),
	};
}
