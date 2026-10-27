import { additions } from "@mod/code-grant";
import { grants, tokenTies } from "@mod/grants";
import { defineModule } from "@mod/kernel";
import { participants } from "@mod/session-participants";
import { revocableKinds } from "@mod/token-control";
import { accessConditions } from "@mod/tokens";
import { familyRevocation, lineage } from "./contract.ts";
import { additionOver, revocationOver } from "./founding/founding.ts";
import { grantOver, grantTakes } from "./grant/grant.ts";
import { conditionOver, families, familyTie, lineageIn } from "./lineage/lineage.ts";
import { section } from "./section.ts";
import { participantOver, revocableOver, settlingTakes } from "./settle/settle.ts";

// Each factory's helpers say what they take; `families` is the module's own.
export default defineModule(
	{ name: "refresh", section, takes: [...settlingTakes, ...grantTakes] },
	(m) => [
		m.contribute(grants).by(grantOver),
		m.contribute(additions).by(additionOver),
		m.provide(families).by(lineageIn),
		m.provide(lineage).by((c) => c.get(families)),
		m.provide(familyRevocation).by(revocationOver),
		m.contribute(tokenTies).by(async (c) => familyTie(await c.get(families))),
		m.contribute(accessConditions).by(conditionOver),
		m.contribute(revocableKinds).by(revocableOver),
		m.contribute(participants).by(participantOver),
	],
);
