import { redemptionHooks } from "@mod/code-grant";
import { tokenTies } from "@mod/grants";
import { type BuildContext, defineModule } from "@mod/kernel";
import { claimsSelections, selectionConsents, selectionRecords } from "./contract.ts";
import { selectionsWith } from "./selections.ts";

const takes = [selectionRecords, selectionConsents];

const built = async (c: Pick<BuildContext<unknown>, "get" | "collect" | "clock">) => {
	const [consent] = await c.collect(selectionConsents);
	return selectionsWith({ records: await c.get(selectionRecords), consent, now: c.clock.now });
};

export default defineModule({ name: "claims-selection", takes }, (m) => [
	m.provide(claimsSelections).by(async (c) => {
		if ((await c.collect(selectionConsents)).length > 1) {
			return c.refuse("claims-selection", "more than one judge of consent");
		}
		return (await built(c)).selections;
	}),
	m.contribute(redemptionHooks).by(async (c) => (await built(c)).hook),
	m.contribute(tokenTies).by(async (c) => (await built(c)).tie),
]);
