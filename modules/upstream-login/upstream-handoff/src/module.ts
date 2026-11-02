import { defineModule } from "@mod/kernel";
import { handoff, handoffIn, handoffTakes } from "./handoff.ts";

export default defineModule(
	{ name: "upstream-handoff", replicaSafe: true, takes: handoffTakes },
	(m) => [m.provide(handoff).by((c) => handoffIn(c))],
);
