import type { AreaScene } from "@mod/conformance";
import {
	type Deployed,
	type Deploying,
	type Instance,
	on as onDeployment,
} from "@mod/conformance/testing";
import type { RevocationScene } from "@mod/conformance-identity";
import { type FakeUpstream, grantsAt, grantsScene, upstreamAt } from "../../grants/test/grants.ts";
import type { GrantsPart } from "../../main.ts";

/** Federation grants on the Redis store, the ledger revoking subjects, with what a scene sets of the grants. */
export const faultScene = (
	corp: FakeUpstream,
	revocations: RevocationScene,
	more: Partial<GrantsPart> = {},
): AreaScene => ({ ...grantsScene(corp, more, { revocations }), storeFaults: true });

/**
 * Runs a scene on a deployment of its own, as the base does, with an upstream its users log in
 * through, started before it and stopped however it ends.
 */
export async function on(
	o: Omit<Deploying, "scene"> & {
		readonly scene: (corp: FakeUpstream) => AreaScene;
	},
	scene: (d: Deployed, corp: FakeUpstream) => Promise<void>,
) {
	const corp = await upstreamAt();
	try {
		await onDeployment({ ...o, scene: o.scene(corp) }, (d) => scene(d, corp));
	} finally {
		await corp.stop();
	}
}

/** What a scene does at the instance: lodging, connecting and calling grants, logging in through the upstream. */
export const grantsOn = (i: Instance, corp: FakeUpstream) => grantsAt(() => i.baseUrl, corp);
