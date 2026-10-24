import { defineModule } from "@mod/kernel";
import { reauths } from "./contract.ts";
import { reauthsOver } from "./reauths.ts";
import { reauthStore } from "./store.ts";

export default defineModule({ name: "reauth", takes: [reauthStore] }, (m) => [
	m.provide(reauths).by(reauthsOver),
]);
