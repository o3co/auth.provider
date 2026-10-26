import { redemptionHooks } from "@mod/code-grant";
import { tokenTies } from "@mod/grants";
import { type BuildContext, defineModule } from "@mod/kernel";
import { claimsSelections, selectionConsents, selectionRecords } from "./contract.ts";
import { type Settings, section } from "./section.ts";
import { selectionsWith } from "./selections.ts";

const takes = [selectionRecords, selectionConsents];

const built = async (c: Pick<BuildContext<Settings>, "get" | "collect" | "clock" | "section">) => {
	const [consent] = await c.collect(selectionConsents);
	return selectionsWith({
		records: await c.get(selectionRecords),
		consent,
		mode: c.section.mode,
		now: c.clock.now,
	});
};

export default defineModule({ name: "claims-selection", section, takes }, (m) => [
	m.provide(claimsSelections).by(async (c) => {
		if ((await c.collect(selectionConsents)).length > 1) {
			return c.refuse("claims-selection", "more than one judge of consent");
		}
		return (await built(c)).selections;
	}),
	m.contribute(redemptionHooks).by(async (c) => (await built(c)).hook),
	m.contribute(tokenTies).by(async (c) => (await built(c)).tie),
]);
