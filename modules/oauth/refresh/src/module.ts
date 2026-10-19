import { additions } from "@mod/code-grant";
import { grants } from "@mod/grants";
import { defineModule } from "@mod/kernel";
import { participants } from "@mod/session-participants";
import { revocableKinds } from "@mod/token-control";
import { accessConditions } from "@mod/tokens";
import { lineage } from "./contract.ts";
import { additionOver, grantOver } from "./grant/grant.ts";
import { conditionOver, lineageIn } from "./lineage/lineage.ts";
import { section } from "./section.ts";
import { participantOver, revocableOver } from "./settle/settle.ts";

export default defineModule({ name: "refresh", section }, (m) => [
	m.contribute(grants).by(grantOver),
	m.contribute(additions).by(additionOver),
	m.provide(lineage).by(lineageIn),
	m.contribute(accessConditions).by(conditionOver),
	m.contribute(revocableKinds).by(revocableOver),
	m.contribute(participants).by(participantOver),
]);
