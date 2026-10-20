import { defineModule } from "@mod/kernel";
import { handoff, handoffIn } from "./handoff.ts";

export default defineModule({ name: "upstream-handoff" }, (m) => [
	m.provide(handoff).by((c) => handoffIn(c)),
]);
