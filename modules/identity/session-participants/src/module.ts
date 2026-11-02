import { defineModule } from "@mod/kernel";
import { closingParticipants } from "@mod/session";
import { closingOf } from "./closing.ts";
import { participants } from "./contract.ts";

export default defineModule(
	{ name: "session-participants", replicaSafe: true, takes: [participants] },
	(m) => [
		m.contribute(closingParticipants).by(async (c) => closingOf(await c.collect(participants))),
	],
);
