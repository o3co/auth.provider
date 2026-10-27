import { redemptionHooks } from "@mod/code-grant";
import { tokenTies } from "@mod/grants";
import { type BuildContext, defineModule } from "@mod/kernel";
import {
	claimScopes,
	claimsSelections,
	constrainedFamilyList,
	selectionConsents,
	selectionRecords,
} from "./contract.ts";
import { type Settings, section } from "./section.ts";
import { selectionsWith } from "./selections.ts";

const takes = [selectionRecords, constrainedFamilyList, selectionConsents, claimScopes];
/** The constrained families' list is swept of those run out this often: best effort, no bound it keeps. */
const sweepMs = 3_600_000;

const built = async (
	c: Pick<BuildContext<Settings>, "get" | "collect" | "clock" | "section" | "log">,
) => {
	const [consent] = await c.collect(selectionConsents);
	const [scopes] = await c.collect(claimScopes);
	return selectionsWith({
		records: await c.get(selectionRecords),
		list: await c.get(constrainedFamilyList),
		log: c.log,
		consent,
		scopes,
		mode: c.section.mode,
		now: c.clock.now,
	});
};

export default defineModule({ name: "claims-selection", section, takes }, (m) => [
	m.provide(claimsSelections).by(async (c) => {
		if ((await c.collect(selectionConsents)).length > 1) {
			return c.refuse("claims-selection", "more than one judge of consent");
		}
		if ((await c.collect(claimScopes)).length > 1) {
			return c.refuse("claims-selection", "more than one table of claim scopes");
		}
		// Off or draining, claims requests go untaken; said at start, so it is never left so unawares.
		if (c.section.mode !== "on")
			c.log.warn("claims-selection.not_taking", { mode: c.section.mode });
		const { selections, sweep } = await built(c);
		if (c.section.mode !== "off") c.every(sweepMs, sweep);
		return selections;
	}),
	m.contribute(redemptionHooks).by(async (c) => (await built(c)).hook),
	m.contribute(tokenTies).by(async (c) => (await built(c)).tie),
]);
