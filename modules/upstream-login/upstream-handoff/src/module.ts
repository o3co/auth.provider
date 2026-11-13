import { erasers } from "@mod/erasure-extensions";
import { defineModule } from "@mod/kernel";
import { heldLoginEraser } from "./eraser.ts";
import { handoff, handoffIn, handoffTakes } from "./handoff.ts";
import { heldLoginStore } from "./store.ts";

export default defineModule(
	{ name: "upstream-handoff", replicaSafe: true, takes: handoffTakes },
	(m) => [
		m.provide(handoff).by((c) => handoffIn(c)),
		// Its build takes only its Store, collecting no probes: the erasure gate collects erasers.
		m.contribute(erasers).by(async (c) => heldLoginEraser(await c.get(heldLoginStore))),
	],
);
