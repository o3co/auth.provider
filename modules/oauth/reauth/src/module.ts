import { defineModule } from "@mod/kernel";
import { reauths } from "./contract.ts";
import { reauthsOver } from "./reauths.ts";
import { section } from "./section.ts";
import { reauthStore } from "./store.ts";

export default defineModule(
	{ name: "reauth", replicaSafe: true, section, takes: [reauthStore] },
	(m) => [m.provide(reauths).by(reauthsOver)],
);
