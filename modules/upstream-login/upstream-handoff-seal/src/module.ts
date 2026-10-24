import { defineModule } from "@mod/kernel";
import { seal } from "@mod/seal";
import { handoffSealing } from "@mod/upstream-handoff";

export default defineModule({ name: "upstream-handoff-seal" }, (m) => [
	m.contribute(handoffSealing).by((c) => c.get(seal)),
]);
