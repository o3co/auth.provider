import { additions } from "@mod/code-grant";
import { grants, tokenTies } from "@mod/grants";
import { defineModule } from "@mod/kernel";
import { revocableKinds } from "@mod/token-control";
import { accessConditions } from "@mod/tokens";
import { lineage } from "./contract.ts";
import { additionOver } from "./founding/founding.ts";
import { grantOver, grantTakes } from "./grant/grant.ts";
import { conditionOver, families, familyTie, lineageIn } from "./lineage/lineage.ts";
import { section } from "./section.ts";
import { revocableOver, settlingTakes } from "./settle/settle.ts";

// Each factory's helpers say what they take; `families` is the module's own.
export default defineModule(
	// Safe on many instances: families, their marks and links are in the shared store, and marking twice
	// does no harm.
	{ name: "refresh", replicaSafe: true, section, takes: [...settlingTakes, ...grantTakes] },
	(m) => [
		m.contribute(grants).by(grantOver),
		m.contribute(additions).by(additionOver),
		m.provide(families).by(lineageIn),
		m.provide(lineage).by((c) => c.get(families)),
		m.contribute(tokenTies).by(async (c) => familyTie(await c.get(families))),
		m.contribute(accessConditions).by(conditionOver),
		m.contribute(revocableKinds).by(revocableOver),
	],
);
